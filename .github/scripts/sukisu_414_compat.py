#!/usr/bin/env python3
"""
Tambalan kompatibilitas SukiSU-Ultra (branch `builtin`) untuk kernel 4.14 non-GKI.
Dijalankan pada salinan di drivers/kernelsu (BUKAN pada fork-mu di GitHub).

Pemakaian:
    python3 sukisu_414_compat.py [--susfs] drivers/kernelsu

Isi:
  1. sulog/event.c   : USER_ARG_NULL aman di KEDUA mode
                       (mode SUSFS minta pointer, mode non-SUSFS minta by-value)
  2. runtime/ksud.c  : panggilan ksu_selinux_hide_* dinetralkan
                       (selinux_hide hanya dikompilasi di kernel >= 5.10)
  3. --susfs saja    : feature/sucompat.c ditambah ksu_handle_faccessat_user /
                       ksu_handle_stat_user (pointer user, sesuai posisi hook 4.14).
                       Varian bawaan mode SUSFS minta `struct filename **`, padahal di
                       4.14 faccessat/vfs_statx belum punya struct filename -> salah baca.

Semua anchor harus cocok persis, kalau tidak -> exit 1.
"""
import pathlib
import re
import sys

SUSFS = "--susfs" in sys.argv
_args = [a for a in sys.argv[1:] if not a.startswith("--")]
S = pathlib.Path(_args[0] if _args else "drivers/kernelsu")


def die(msg):
    print(f"[FAIL] {msg}", file=sys.stderr)
    sys.exit(1)


def read(rel):
    p = S / rel
    if not p.is_file():
        die(f"{rel} tidak ada")
    return p, p.read_text()


# ------------------------------------------------------------ 1. sulog/event.c
def fix_user_arg_null():
    p, src = read("sulog/event.c")
    old = "    #define USER_ARG_NULL user_arg_null_ptr()\n"
    new = (
        "#ifdef CONFIG_KSU_SUSFS\n"
        "    #define USER_ARG_NULL user_arg_null_ptr()\n"
        "#else\n"
        "    #define USER_ARG_NULL (*user_arg_null_ptr())\n"
        "#endif\n"
    )
    if new in src:
        print("[skip] sulog/event.c: sudah dipatch")
        return
    if src.count(old) != 1:
        die(f"sulog/event.c: anchor USER_ARG_NULL ditemukan {src.count(old)}x (harus 1x)")
    p.write_text(src.replace(old, new))
    print("[ok]   sulog/event.c: USER_ARG_NULL kondisional per mode")


# ------------------------------------------------------------ 2. runtime/ksud.c
def neutralize_selinux_hide():
    p, src = read("runtime/ksud.c")
    n = src.count("ksu_selinux_hide_")
    if n == 0:
        print("[skip] runtime/ksud.c: selinux_hide sudah dinetralkan")
        return
    if n != 4:
        die(f"runtime/ksud.c: jumlah ksu_selinux_hide_ = {n} (diharapkan 4) - struktur upstream berubah")
    out = re.sub(
        r"(?m)^([ \t]*)ksu_selinux_hide_[a-z_]+\(\);",
        r"\1((void)0); /* 4.14: selinux_hide tidak dikompilasi */",
        src,
    )
    if "ksu_selinux_hide_" in out:
        die("runtime/ksud.c: masih ada ksu_selinux_hide_ setelah dinetralkan")
    p.write_text(out)
    print("[ok]   runtime/ksud.c: selinux_hide dinetralkan")


# ------------------------------------------------------------ 3. sucompat.c (SUSFS)
USER_FUNCS = r'''

#ifdef CONFIG_KSU_SUSFS
/*
 * 4.14: titik hook faccessat / vfs_statx menerima pointer USER, bukan struct filename.
 * Varian bawaan mode SUSFS (struct filename **) tidak bisa dipakai di sini, jadi
 * logikanya sama dengan varian non-SUSFS yang sudah terbukti jalan.
 */
static __always_inline bool ksu_is_su_allowed_user(const char __user *const *p)
{
    if (!ksu_su_compat_enabled)
        return false;

    if (likely(test_thread_flag(TIF_SECCOMP)))
        return false;

    if (!ksu_is_allow_uid_for_current(current_uid().val))
        return false;

    if (unlikely(!p || !*p))
        return false;

    return true;
}

static noinline void ksu_sucompat_user_to_sh(const char __user **filename_user, const char *syscall_name)
{
    char path[sizeof(su_path)] = { 0 }; // sizeof includes nullterm already!
    long len = ksu_strncpy_from_user_nofault(path, *filename_user, sizeof(path));
    char __user *sh;

    if (unlikely(len <= 0))
        return;

    if (likely(memcmp(path, su_path, sizeof(su_path))))
        return;

    sh = sh_user_path();
    if (!sh)
        return;

    pr_info("%s su->sh!\n", syscall_name);
    *filename_user = sh;
}

int ksu_handle_faccessat_user(int *dfd, const char __user **filename_user, int *mode, int *__unused_flags)
{
    if (!ksu_is_su_allowed_user(filename_user))
        return 0;

    ksu_sucompat_user_to_sh(filename_user, "faccessat");
    return 0;
}

int ksu_handle_stat_user(int *dfd, const char __user **filename_user, int *flags)
{
    if (!ksu_is_su_allowed_user(filename_user))
        return 0;

    ksu_sucompat_user_to_sh(filename_user, "newfstatat");
    return 0;
}
#endif /* CONFIG_KSU_SUSFS */
'''


def add_user_hooks():
    p, src = read("feature/sucompat.c")
    if "ksu_handle_faccessat_user" in src:
        print("[skip] feature/sucompat.c: varian *_user sudah ada")
        return
    # sanity: pastikan helper yang kita pakai memang ada di file ini
    for need in ("sh_user_path", "static const char su_path[]", "ksu_su_compat_enabled"):
        if need not in src:
            die(f"feature/sucompat.c: '{need}' tidak ditemukan - struktur upstream berubah")
    if "void __exit ksu_sucompat_exit(void)" not in src:
        die("feature/sucompat.c: ksu_sucompat_exit tidak ditemukan - struktur upstream berubah")
    p.write_text(src.rstrip("\n") + "\n" + USER_FUNCS)
    print("[ok]   feature/sucompat.c: ksu_handle_{faccessat,stat}_user ditambahkan")


def main():
    fix_user_arg_null()
    neutralize_selinux_hide()
    if SUSFS:
        add_user_hooks()
    print("[+] Kompat SukiSU 4.14 selesai (%s)." % ("mode SUSFS" if SUSFS else "tanpa SUSFS"))


if __name__ == "__main__":
    main()
