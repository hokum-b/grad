#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <ctype.h>

static int colour_on = 0;

#define CLR_BOLD   (colour_on ? "\033[1m"   : "")
#define CLR_DIM    (colour_on ? "\033[2m"   : "")
#define CLR_GREEN  (colour_on ? "\033[32m"  : "")
#define CLR_YELLOW (colour_on ? "\033[33m"  : "")
#define CLR_RED    (colour_on ? "\033[31m"  : "")
#define CLR_CYAN   (colour_on ? "\033[36m"  : "")
#define CLR_RESET  (colour_on ? "\033[0m"   : "")

#define SYS_DB  "/etc/grad/installed"

static void die(const char *msg)
{
    fprintf(stderr, "%serror%s: %s\n", CLR_RED, CLR_RESET, msg);
    exit(1);
}

static void step(const char *label, const char *detail)
{
    printf("%s::%s %-12s%s %s\n", CLR_CYAN, CLR_RESET, label, CLR_DIM, detail);
    fflush(stdout);
}

static void ok(const char *label, const char *detail)
{
    printf("%s ok%s  %-12s%s %s%s\n",
           CLR_GREEN, CLR_RESET, label, CLR_DIM, detail, CLR_RESET);
}

static void detect_os(char *out, size_t len)
{
    FILE *f = fopen("/etc/os-release", "r");
    if (!f) { snprintf(out, len, "unknown"); return; }
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "ID=", 3) == 0) {
            char *val = line + 3;
            size_t vl = strlen(val);
            while (vl > 0 && (val[vl-1] == '\n' || val[vl-1] == '\r' ||
                              val[vl-1] == '"'  || val[vl-1] == '\''))
                val[--vl] = '\0';
            if (val[0] == '"' || val[0] == '\'') { val++; }
            snprintf(out, len, "%s", val);
            fclose(f);
            return;
        }
    }
    fclose(f);
    snprintf(out, len, "unknown");
}

static const char *pkg_install_cmd(const char *os_id)
{
    if (strcmp(os_id, "debian")  == 0 ||
        strcmp(os_id, "ubuntu")  == 0 ||
        strcmp(os_id, "linuxmint") == 0 ||
        strcmp(os_id, "pop")     == 0)
        return "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y";

    if (strcmp(os_id, "arch")    == 0 ||
        strcmp(os_id, "manjaro") == 0 ||
        strcmp(os_id, "endeavouros") == 0)
        return "sudo pacman -S --noconfirm --needed";

    if (strcmp(os_id, "alpine")  == 0 ||
        strcmp(os_id, "chimera") == 0)
        return "sudo apk add --no-cache";

    if (strcmp(os_id, "fedora")  == 0 ||
        strcmp(os_id, "rhel")    == 0 ||
        strcmp(os_id, "centos")  == 0)
        return "sudo dnf install -y";

    if (strcmp(os_id, "opensuse-leap")       == 0 ||
        strcmp(os_id, "opensuse-tumbleweed") == 0)
        return "sudo zypper install -y";

    if (strcmp(os_id, "void") == 0)
        return "sudo xbps-install -y";

    return NULL;
}

static char *extract_var(const char *path, const char *key)
{
    FILE *f = fopen(path, "r");
    if (!f) return NULL;

    size_t klen = strlen(key);
    char line[4096];
    char *result = NULL;

    while (fgets(line, sizeof(line), f)) {
        size_t ll = strlen(line);
        while (ll > 0 && (line[ll-1] == '\r' || line[ll-1] == '\n'))
            line[--ll] = '\0';

        if (ll < klen + 1) continue;
        int match = 1;
        for (size_t i = 0; i < klen; i++) {
            char a = key[i], b = line[i];
            if (a == '-' || a == '_') a = '-';
            if (b == '-' || b == '_') b = '-';
            if (a != b) { match = 0; break; }
        }
        if (!match || line[klen] != '=') continue;

        char *val = line + klen + 1;
        if (val[0] == '"' || val[0] == '\'') {
            char q = val[0];
            val++;
            char *end = strrchr(val, q);
            if (end) *end = '\0';
        }
        result = strdup(val);
        break;
    }
    fclose(f);
    return result;
}

static char *expand_vars(const char *s, const char *pkgname, const char *pkgver)
{
    char *out = malloc(4096);
    out[0] = '\0';
    size_t oi = 0;
    for (size_t i = 0; s[i]; ) {
        if (s[i] == '$' && s[i+1] == '{') {
            size_t j = i + 2;
            while (s[j] && s[j] != '}') j++;
            size_t varlen = j - (i + 2);
            char varname[64] = {0};
            if (varlen < sizeof(varname))
                memcpy(varname, s + i + 2, varlen);
            const char *rep = "";
            if (strcmp(varname, "pkgname") == 0) rep = pkgname;
            else if (strcmp(varname, "pkgver") == 0)  rep = pkgver;
            size_t rl = strlen(rep);
            memcpy(out + oi, rep, rl);
            oi += rl;
            i = j + 1;
        } else {
            out[oi++] = s[i++];
        }
    }
    out[oi] = '\0';
    return out;
}

static void install_deps(const char *build_file_abs, const char *os_id)
{
    const char *install_cmd = pkg_install_cmd(os_id);

    char processed[] = "/tmp/grad.processed.XXXXXX";
    int pfd = mkstemp(processed);
    if (pfd < 0) return;
    close(pfd);
    char preproc[PATH_MAX * 2 + 64];
    snprintf(preproc, sizeof(preproc),
             "sed -E -e 's/\\r$//' "
             "-e 's/^([a-zA-Z0-9_]+)-([a-zA-Z0-9_]+)=/\\1_\\2=/' "
             "'%s' > '%s'",
             build_file_abs, processed);
    system(preproc);

    char collector[] = "/tmp/grad.deplist.XXXXXX";
    int cfd = mkstemp(collector);
    if (cfd < 0) { unlink(processed); return; }
    FILE *cf = fdopen(cfd, "w");
    if (!cf) { close(cfd); unlink(processed); return; }

    fprintf(cf,
        "#!/bin/bash\n"
        "OS_ID='%s'\n"
        "use_git=false\n"
        "__BUILD_DEPS=()\n"
        "__RUNTIME_DEPS=()\n"
        "register_dep() {\n"
        "    local td=\"$1\"; shift\n"
        "    local in_build=false\n"
        "    [ \"$td\" = \"$OS_ID\" ] || [ \"$td\" = \"any\" ] || return 0\n"
        "    for arg in \"$@\"; do\n"
        "        if [ \"$arg\" = '--build' ]; then in_build=true; continue; fi\n"
        "        if $in_build; then __BUILD_DEPS+=(\"$arg\")\n"
        "        else              __RUNTIME_DEPS+=(\"$arg\"); fi\n"
        "    done\n"
        "}\n"
        "get_build_tool() { echo make; }\n"
        "install_binary() { :; }\n"
        "install_license() { :; }\n"
        "prepare() { :; }\n"
        "build() { :; }\n"
        "package() { :; }\n"
        ". '%s'\n"
        "for d in \"${__BUILD_DEPS[@]}\"; do echo \"BUILD:$d\"; done\n"
        "for d in \"${__RUNTIME_DEPS[@]}\"; do echo \"RUNTIME:$d\"; done\n",
        os_id, processed);

    fclose(cf);
    chmod(collector, 0700);

    char collect_cmd[PATH_MAX + 32];
    snprintf(collect_cmd, sizeof(collect_cmd), "bash '%s' 2>/dev/null", collector);
    FILE *pipe = popen(collect_cmd, "r");

    char build_deps[4096]   = "";
    char runtime_deps[4096] = "";

    if (pipe) {
        char line[256];
        while (fgets(line, sizeof(line), pipe)) {
            line[strcspn(line, "\r\n")] = '\0';
            if (strncmp(line, "BUILD:", 6) == 0) {
                if (strlen(build_deps) > 0) strcat(build_deps, " ");
                strcat(build_deps, line + 6);
            } else if (strncmp(line, "RUNTIME:", 8) == 0) {
                if (strlen(runtime_deps) > 0) strcat(runtime_deps, " ");
                strcat(runtime_deps, line + 8);
            }
        }
        pclose(pipe);
    }

    unlink(collector);
    unlink(processed);

    if (strlen(build_deps) > 0)
        printf("%s   build    %s%s\n", CLR_DIM, build_deps, CLR_RESET);
    if (strlen(runtime_deps) > 0)
        printf("%s   runtime  %s%s\n", CLR_DIM, runtime_deps, CLR_RESET);

    if (!install_cmd) {
        printf("%s   warning  unknown distro '%s', skipping dep install%s\n",
               CLR_YELLOW, os_id, CLR_RESET);
        return;
    }

    if (strlen(build_deps) > 0) {
        char dep_cmd[8192];
        snprintf(dep_cmd, sizeof(dep_cmd), "%s %s", install_cmd, build_deps);
        if (system(dep_cmd) != 0)
            fprintf(stderr, "%s   warning  some build deps may not have installed%s\n",
                    CLR_YELLOW, CLR_RESET);
    }
}

static int run_hook(const char *build_file_abs, const char *hook,
                    const char *work_dir, const char *os_id,
                    const char *pkgname)
{
    char tmp_path[] = "/tmp/grad.hook.XXXXXX";
    int fd = mkstemp(tmp_path);
    if (fd < 0) return -1;
    FILE *f = fdopen(fd, "w");
    if (!f) { close(fd); return -1; }

    char processed[] = "/tmp/grad.processed.XXXXXX";
    int pfd = mkstemp(processed);
    if (pfd < 0) { fclose(f); unlink(tmp_path); return -1; }
    close(pfd);
    char preproc[PATH_MAX * 2 + 64];
    snprintf(preproc, sizeof(preproc),
             "sed -E -e 's/\\r$//' "
             "-e 's/^([a-zA-Z0-9_]+)-([a-zA-Z0-9_]+)=/\\1_\\2=/' "
             "'%s' > '%s'",
             build_file_abs, processed);
    system(preproc);

    const char *build_tool = "make";
    if (strcmp(os_id, "chimera") == 0 || strcmp(os_id, "void") == 0)
        build_tool = "gmake";

    fprintf(f,
        "#!/bin/bash\n"
        "set -e\n"
        "OS_ID='%s'\n"
        "use_git=false\n"
        "register_dep() {\n"
        "    local td=\"$1\"; shift\n"
        "    [ \"$td\" = \"$OS_ID\" ] || [ \"$td\" = \"any\" ] || return 0\n"
        "}\n"
        "get_build_tool() { echo '%s'; }\n"
        "install_binary() {\n"
        "    local b=\"$1\"\n"
        "    if [ \"$(id -u)\" = '0' ]; then\n"
        "        install -Dm755 \"$b\" \"/usr/local/bin/$b\"\n"
        "    else\n"
        "        sudo install -Dm755 \"$b\" \"/usr/local/bin/$b\"\n"
        "    fi\n"
        "}\n"
        "install_license() {\n"
        "    local l=\"$1\"\n"
        "    if [ \"$(id -u)\" = '0' ]; then\n"
        "        install -Dm644 \"$l\" \"/usr/local/share/licenses/%s/$l\"\n"
        "    else\n"
        "        sudo install -Dm644 \"$l\" \"/usr/local/share/licenses/%s/$l\"\n"
        "    fi\n"
        "}\n"
        ". '%s'\n"
        "cd '%s'\n"
        "%s\n",
        os_id, build_tool, pkgname, pkgname,
        processed, work_dir, hook);

    fclose(f);
    chmod(tmp_path, 0700);

    int ret = system(tmp_path);
    unlink(tmp_path);
    unlink(processed);
    return (WIFEXITED(ret) && WEXITSTATUS(ret) == 0) ? 0 : -1;
}

static int mkdirp(const char *path, mode_t mode)
{
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') { *p = '\0'; mkdir(tmp, mode); *p = '/'; }
    }
    return mkdir(tmp, mode);
}

static void record(const char *path, const char *name,
                   const char *ver, const char *src, const char *sha)
{
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s", path);
    mkdirp(dirname(tmp), 0755);

    FILE *f = fopen(path, "a");
    if (!f) {
        char cmd[PATH_MAX * 2 + 128];
        snprintf(tmp, sizeof(tmp), "%s", path);
        snprintf(cmd, sizeof(cmd),
                 "sudo mkdir -p '%s' && "
                 "printf '%%s|%%s|%%s|%%s\\n' '%s' '%s' '%s' '%s' "
                 "| sudo tee -a '%s' >/dev/null",
                 dirname(tmp), name, ver, src, sha, path);
        system(cmd);
        return;
    }
    fprintf(f, "%s|%s|%s|%s\n", name, ver, src, sha);
    fclose(f);
}

static void cmd_install(const char *build_file_arg)
{
    char build_file[PATH_MAX];
    if (!realpath(build_file_arg, build_file))
        die("build file not found");

    char os_id[64];
    detect_os(os_id, sizeof(os_id));

    char *pkgname = extract_var(build_file, "pkgname");
    char *pkgver  = extract_var(build_file, "pkgver");
    char *src_raw = extract_var(build_file, "source_tarball");
    char *sha256  = extract_var(build_file, "sha256_tarball");

    if (!pkgname || !pkgver || !src_raw || !sha256)
        die("missing required fields in grad.build");

    char *source = expand_vars(src_raw, pkgname, pkgver);

    printf("\n%s%s %s%s  %s(%s)%s\n\n",
           CLR_BOLD, pkgname, pkgver, CLR_RESET,
           CLR_DIM, os_id, CLR_RESET);

    step("deps", "");
    install_deps(build_file, os_id);
    ok("deps", "");

    char work_dir[] = "/tmp/grad.XXXXXX";
    if (!mkdtemp(work_dir)) die("mkdtemp failed");

    step("fetch", source);
    char tarball[PATH_MAX];
    const char *bn = strrchr(source, '/');
    snprintf(tarball, sizeof(tarball), "%s/%s", work_dir, bn ? bn + 1 : source);

    char dl_cmd[PATH_MAX * 2 + 64];
    if (strncmp(source, "http", 4) == 0) {
        snprintf(dl_cmd, sizeof(dl_cmd),
                 "curl -fsSL -o '%s' '%s' 2>/dev/null || wget -q -O '%s' '%s'",
                 tarball, source, tarball, source);
    } else {
        snprintf(dl_cmd, sizeof(dl_cmd), "cp '%s' '%s'", source, tarball);
    }
    if (system(dl_cmd) != 0) die("download failed");
    ok("fetch", bn ? bn + 1 : source);

    step("verify", "sha256");
    char verify_cmd[PATH_MAX + 128];
    snprintf(verify_cmd, sizeof(verify_cmd),
             "echo '%s  %s' | sha256sum -c - >/dev/null 2>&1",
             sha256, tarball);
    if (system(verify_cmd) != 0) die("sha256 mismatch");
    ok("verify", "ok");

    step("extract", "");
    char extract_cmd[PATH_MAX + 32];
    snprintf(extract_cmd, sizeof(extract_cmd),
             "tar -xf '%s' -C '%s'", tarball, work_dir);
    if (system(extract_cmd) != 0) die("extraction failed");
    ok("extract", "");

    const char *hooks[] = { "prepare", "build", "package" };
    for (int i = 0; i < 3; i++) {
        step(hooks[i], "");
        if (run_hook(build_file, hooks[i], work_dir, os_id, pkgname) != 0)
            die(hooks[i]);
        ok(hooks[i], "");
    }

    const char *home = getenv("HOME");
    char user_db[PATH_MAX];
    if (home) snprintf(user_db, sizeof(user_db), "%s/.grad/installed", home);
    else      snprintf(user_db, sizeof(user_db), "/tmp/grad.installed");

    step("record", "");
    record(SYS_DB,  pkgname, pkgver, source, sha256);
    record(user_db, pkgname, pkgver, source, sha256);
    ok("record", "");

    char rm_cmd[PATH_MAX + 8];
    snprintf(rm_cmd, sizeof(rm_cmd), "rm -rf '%s'", work_dir);
    system(rm_cmd);

    printf("\n%s✓%s  %s%s%s  %s(%s)%s\n\n",
           CLR_GREEN, CLR_RESET,
           CLR_BOLD, pkgname, CLR_RESET,
           CLR_DIM, pkgver, CLR_RESET);

    free(pkgname); free(pkgver); free(src_raw); free(source); free(sha256);
}

static void cmd_list(void)
{
    const char *home = getenv("HOME");
    char user_db[PATH_MAX];
    if (home) snprintf(user_db, sizeof(user_db), "%s/.grad/installed", home);
    else      snprintf(user_db, sizeof(user_db), "/tmp/grad.installed");

    const char *paths[2]  = { SYS_DB, user_db };
    const char *labels[2] = { "system", "user" };

    for (int pi = 0; pi < 2; pi++) {
        printf("%s── %s%s\n", CLR_DIM, labels[pi], CLR_RESET);
        FILE *f = fopen(paths[pi], "r");
        if (!f) {
            printf("   %s(none)%s\n", CLR_DIM, CLR_RESET);
        } else {
            char line[4096];
            int count = 0;
            while (fgets(line, sizeof(line), f)) {
                line[strcspn(line, "\r\n")] = '\0';
                char *name = strtok(line, "|");
                char *ver  = strtok(NULL, "|");
                char *src  = strtok(NULL, "|");
                char *sha  = strtok(NULL, "|");
                if (!name || !ver) continue;
                printf("   %s%s%s %s(%s)%s\n",
                       CLR_BOLD, name, CLR_RESET,
                       CLR_DIM, ver, CLR_RESET);
                if (src) printf("   %s   src  %s%s\n",     CLR_DIM, src, CLR_RESET);
                if (sha) printf("   %s   sha  %.16s…%s\n", CLR_DIM, sha, CLR_RESET);
                count++;
            }
            fclose(f);
            if (!count) printf("   %s(none)%s\n", CLR_DIM, CLR_RESET);
        }
        printf("\n");
    }
}

int main(int argc, char *argv[])
{
    colour_on = isatty(STDOUT_FILENO);

    if (argc < 2) {
        fprintf(stderr, "usage: grad <install <build_file> | list>\n");
        return 1;
    }

    if (strcmp(argv[1], "install") == 0) {
        if (argc < 3) {
            fprintf(stderr, "usage: grad install <path/to/grad.build>\n");
            return 1;
        }
        cmd_install(argv[2]);
    } else if (strcmp(argv[1], "list") == 0) {
        cmd_list();
    } else {
        fprintf(stderr, "usage: grad <install <build_file> | list>\n");
        return 1;
    }

    return 0;
}
