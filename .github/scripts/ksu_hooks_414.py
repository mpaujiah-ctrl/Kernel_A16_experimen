#!/usr/bin/env python3
"""
Pasang hook manual SukiSU-Ultra (branch `builtin`, TANPA SUSFS) ke kernel 4.14
tree DEVS (lineage-23.2, cepheus).

Pemakaian (dari root source kernel):
    python3 ksu_hooks_414.py [--susfs] [path_kernel]

  tanpa --susfs : mode manual-hook biasa (SukiSU build TANPA SUSFS)
  dengan --susfs: mode "SUSFS inline" (CONFIG_KSU_SUSFS=y). Bedanya:
      * faccessat/stat memanggil varian *_user (pointer user, cocok untuk 4.14),
        BUKAN varian struct filename** milik SukiSU mode SUSFS
      * vfs_read dijaga static key (ksu_is_init_rc_hook_enabled), bukan bool
      * ditambah hook setresuid di kernel/sys.c (LSM setuid dimatikan di mode SUSFS)
    Varian *_user disediakan oleh sukisu_414_compat.py --susfs.

Aturan:
  - Setiap anchor harus ketemu TEPAT 1x, kalau tidak -> exit 1 (nggak ada gagal diam-diam).
  - File yang sudah ada `CONFIG_KSU`-nya dilewati (aman dijalankan ulang).
  - Semua hook dibungkus #ifdef CONFIG_KSU.

Hook yang dipasang (sesuai definisi non-SUSFS di SukiSU builtin):
  kernel/reboot.c   -> ksu_handle_sys_reboot   (jalur komunikasi manager)
  fs/exec.c         -> ksu_handle_execveat     (su compat + trigger ksud)
  fs/open.c         -> ksu_handle_faccessat    (su compat)
  fs/stat.c         -> ksu_handle_stat         (su compat)
  fs/read_write.c   -> ksu_handle_vfs_read     (injeksi init.rc)

Nggak perlu dipasang di mode ini:
  setresuid  -> sudah lewat LSM hook (ksu_task_fix_setuid)
  input      -> ksu_handle_input_handle_event itu dead code (pakai input handler)
  devpts     -> ksu_handle_devpts itu dead code
"""
import pathlib
import sys

SUSFS = "--susfs" in sys.argv
# varian *_user hanya didefinisikan kalau CONFIG_KSU_SUSFS=y
USER_GUARD = "CONFIG_KSU_SUSFS" if SUSFS else "CONFIG_KSU"
_args = [a for a in sys.argv[1:] if not a.startswith("--")]
ROOT = pathlib.Path(_args[0] if _args else ".")
# marker idempotensi: JANGAN pakai "CONFIG_KSU" (patch SUSFS sudah memuat CONFIG_KSU_SUSFS_*)
MARK = "ksu_handle_"


def die(msg):
    print(f"[FAIL] {msg}", file=sys.stderr)
    sys.exit(1)


def once(src, needle, rel):
    n = src.count(needle)
    if n != 1:
        die(f"{rel}: anchor ditemukan {n}x (harus tepat 1x): {needle[:70]!r}")
    return src.index(needle)


def insert_decl(src, func_sig, hint, text, rel):
    """Taruh deklarasi extern tepat di atas fungsi (di atas doc-comment kalau menempel)."""
    i = once(src, func_sig, rel)
    c = src.rfind("/*", 0, i)
    if c != -1 and hint and hint in src[c:i] and src[c:i].rstrip().endswith("*/"):
        i = c
    return src[:i] + text + src[i:]


def insert_after(src, anchor, text, rel):
    i = once(src, anchor, rel) + len(anchor)
    return src[:i] + text + src[i:]


def patch(rel, fn):
    p = ROOT / rel
    if not p.is_file():
        die(f"{rel} tidak ada")
    src = p.read_text()
    if MARK in src:
        print(f"[skip] {rel}: sudah ada hook KSU")
        return
    out = fn(src, rel)
    p.write_text(out)
    print(f"[ok]   {rel}")


# ---------------------------------------------------------------- reboot.c
def do_reboot(src, rel):
    decl = (
        "#ifdef CONFIG_KSU\n"
        "extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd,\n"
        "\t\t\t\t void __user **arg);\n"
        "#endif\n\n"
    )
    src = insert_decl(
        src,
        "SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,",
        "Reboot system call",
        decl,
        rel,
    )
    call = (
        "\n#ifdef CONFIG_KSU\n"
        "\tksu_handle_sys_reboot(magic1, magic2, cmd, &arg);\n"
        "#endif\n"
    )
    return insert_after(
        src, "\tchar buffer[256];\n\tint ret = 0;\n", call, rel
    )


# ---------------------------------------------------------------- exec.c
def do_exec(src, rel):
    sig = (
        "static int do_execveat_common(int fd, struct filename *filename,\n"
        "\t\t\t      struct user_arg_ptr argv,\n"
        "\t\t\t      struct user_arg_ptr envp,\n"
        "\t\t\t      int flags)\n"
        "{\n"
    )
    decl = (
        "#ifdef CONFIG_KSU\n"
        "extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr,\n"
        "\t\t\t       void *argv, void *envp, int *flags);\n"
        "#endif\n\n"
    )
    src = insert_decl(src, sig, None, decl, rel)
    call = (
        "#ifdef CONFIG_KSU\n"
        "\tksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);\n"
        "#endif\n"
    )
    return insert_after(src, sig, call, rel)


# ---------------------------------------------------------------- open.c
def do_open(src, rel):
    fn = "ksu_handle_faccessat_user" if SUSFS else "ksu_handle_faccessat"
    sig = "SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)\n{\n"
    decls = (
        "\tconst struct cred *old_cred;\n"
        "\tstruct cred *override_cred;\n"
        "\tstruct path path;\n"
        "\tstruct inode *inode;\n"
        "\tstruct vfsmount *mnt;\n"
        "\tint res;\n"
        "\tunsigned int lookup_flags = LOOKUP_FOLLOW;\n"
    )
    decl = (
        f"#ifdef {USER_GUARD}\n"
        f"extern int {fn}(int *dfd, const char __user **filename_user,\n"
        "\t\t\t\tint *mode, int *__unused_flags);\n"
        "#endif\n\n"
    )
    src = insert_decl(src, sig, "access() needs", decl, rel)
    call = (
        f"\n#ifdef {USER_GUARD}\n"
        f"\t{fn}(&dfd, &filename, &mode, NULL);\n"
        "#endif\n"
    )
    return insert_after(src, sig + decls, call, rel)


# ---------------------------------------------------------------- stat.c
def do_stat(src, rel):
    fn = "ksu_handle_stat_user" if SUSFS else "ksu_handle_stat"
    sig = "int vfs_statx(int dfd, const char __user *filename, int flags,\n"
    full = (
        sig
        + "\t      struct kstat *stat, u32 request_mask)\n"
        "{\n"
        "\tstruct path path;\n"
        "\tint error = -EINVAL;\n"
        "\tunsigned int lookup_flags = LOOKUP_FOLLOW | LOOKUP_AUTOMOUNT;\n"
    )
    decl = (
        f"#ifdef {USER_GUARD}\n"
        f"extern int {fn}(int *dfd, const char __user **filename_user,\n"
        "\t\t\t   int *flags);\n"
        "#endif\n\n"
    )
    src = insert_decl(src, sig, "vfs_statx - Get basic and extra", decl, rel)
    call = (
        f"\n#ifdef {USER_GUARD}\n"
        f"\t{fn}(&dfd, &filename, &flags);\n"
        "#endif\n"
    )
    return insert_after(src, full, call, rel)


# ---------------------------------------------------------------- read_write.c
def do_read(src, rel):
    sig = (
        "ssize_t vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)\n"
        "{\n"
        "\tssize_t ret;\n"
    )
    if SUSFS:
        # mode SUSFS: ksu_vfs_read_hook (bool) tidak pernah dimatikan, pakai static key
        decl = (
            "#ifdef CONFIG_KSU_SUSFS\n"
            "extern struct static_key_true ksu_is_init_rc_hook_enabled;\n"
            "extern int ksu_handle_vfs_read(struct file **file_ptr, char __user **buf_ptr,\n"
            "\t\t\t\tsize_t *count_ptr, loff_t **pos);\n"
            "#endif\n\n"
        )
    else:
        decl = (
            "#ifdef CONFIG_KSU\n"
            "extern bool ksu_vfs_read_hook;\n"
            "extern int ksu_handle_vfs_read(struct file **file_ptr, char __user **buf_ptr,\n"
            "\t\t\t\tsize_t *count_ptr, loff_t **pos);\n"
            "#endif\n\n"
        )
    src = insert_decl(
        src,
        "ssize_t vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)\n{",
        None,
        decl,
        rel,
    )
    if SUSFS:
        call = (
            "\n#ifdef CONFIG_KSU_SUSFS\n"
            "\tif (static_branch_unlikely(&ksu_is_init_rc_hook_enabled))\n"
            "\t\tksu_handle_vfs_read(&file, &buf, &count, &pos);\n"
            "#endif\n"
        )
    else:
        call = (
            "\n#ifdef CONFIG_KSU\n"
            "\tif (unlikely(ksu_vfs_read_hook))\n"
            "\t\tksu_handle_vfs_read(&file, &buf, &count, &pos);\n"
            "#endif\n"
        )
    return insert_after(src, sig, call, rel)


# ---------------------------------------------------------------- sys.c (SUSFS saja)
def do_sys(src, rel):
    sig = "SYSCALL_DEFINE3(setresuid, uid_t, ruid, uid_t, euid, uid_t, suid)\n"
    full = (
        sig
        + "{\n"
        "\tstruct user_namespace *ns = current_user_ns();\n"
        "\tconst struct cred *old;\n"
        "\tstruct cred *new;\n"
        "\tint retval;\n"
        "\tkuid_t kruid, keuid, ksuid;\n"
    )
    decl = (
        "#ifdef CONFIG_KSU_SUSFS\n"
        "extern int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid);\n"
        "#endif\n\n"
    )
    src = insert_decl(src, sig, None, decl, rel)
    call = (
        "\n#ifdef CONFIG_KSU_SUSFS\n"
        "\tksu_handle_setresuid(ruid, euid, suid);\n"
        "#endif\n"
    )
    return insert_after(src, full, call, rel)


def main():
    patch("kernel/reboot.c", do_reboot)
    patch("fs/exec.c", do_exec)
    patch("fs/open.c", do_open)
    patch("fs/stat.c", do_stat)
    patch("fs/read_write.c", do_read)
    if SUSFS:
        patch("kernel/sys.c", do_sys)
    print("[+] Semua hook SukiSU terpasang (%s)." % ("mode SUSFS" if SUSFS else "tanpa SUSFS"))


if __name__ == "__main__":
    main()
