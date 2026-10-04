#!/usr/bin/env python3
"""
Perbaiki 2 hunk SUSFS v2.3.0 (patch 4.14) yang selalu ditolak di tree DEVS:

  fs/namei.c      hunk #21 -> do_tmpfile (tail) + do_o_path + deklarasi path_openat
                  (DEVS: vfs_open() cuma 2 argumen, patch mengharapkan 3 -> konteks beda)
  fs/proc/cmdline.c hunk #1 -> DEVS punya blok CONFIG_INITRAMFS_IGNORE_SKIP_FLAG

Jalankan SETELAH `patch -p1 < susfs_patch_to_4.14.patch` (tanpa --fuzz=0):
    python3 susfs_devs_fixups.py [path_kernel]

Semua anchor harus ketemu TEPAT 1x, kalau tidak -> exit 1.
Aman dijalankan ulang (dilewati kalau sudah ada).
"""
import pathlib
import sys

ROOT = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".")


def die(msg):
    print(f"[FAIL] {msg}", file=sys.stderr)
    sys.exit(1)


def once(src, needle, rel):
    n = src.count(needle)
    if n != 1:
        die(f"{rel}: anchor ditemukan {n}x (harus tepat 1x): {needle[:80]!r}")
    return src.index(needle)


def replace_once(src, old, new, rel):
    i = once(src, old, rel)
    return src[:i] + new + src[i + len(old):]


# ------------------------------------------------------------------ namei.c
def fix_namei(src, rel):
    # (a) ekor do_tmpfile: putname(fake_filename)
    #     (deklarasi & pemakaian di awal do_tmpfile sudah masuk lewat hunk lain)
    old_tail = (
        "out2:\n"
        "\tmnt_drop_write(path.mnt);\n"
        "out:\n"
        "\tpath_put(&path);\n"
        "\treturn error;\n"
        "}\n"
        "\n"
        "static int do_o_path("
    )
    new_tail = (
        "out2:\n"
        "\tmnt_drop_write(path.mnt);\n"
        "out:\n"
        "\tpath_put(&path);\n"
        "#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT\n"
        "\tif (fake_filename && !IS_ERR(fake_filename))\n"
        "\t\tputname(fake_filename);\n"
        "#endif // #ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT\n"
        "\treturn error;\n"
        "}\n"
        "\n"
        "static int do_o_path("
    )
    src = replace_once(src, old_tail, new_tail, rel)

    # (b) do_o_path (versi DEVS: vfs_open 2 argumen)
    old_o_path = (
        "static int do_o_path(struct nameidata *nd, unsigned flags, struct file *file)\n"
        "{\n"
        "\tstruct path path;\n"
        "\tint error = path_lookupat(nd, flags, &path);\n"
        "\tif (!error) {\n"
        "\t\taudit_inode(nd->name, path.dentry, 0);\n"
        "\t\terror = vfs_open(&path, file);\n"
        "\t\tpath_put(&path);\n"
        "\t}\n"
        "\treturn error;\n"
        "}\n"
    )
    new_o_path = (
        "static int do_o_path(struct nameidata *nd, unsigned flags, struct file *file)\n"
        "{\n"
        "#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT\n"
        "\tint old_dfd = nd->dfd;\n"
        "\tstruct filename *fake_filename = NULL;\n"
        "#endif // #ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT\n"
        "\tstruct path path;\n"
        "\tint error = path_lookupat(nd, flags, &path);\n"
        "\tif (!error) {\n"
        "#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT\n"
        "\t\tif (old_dfd != -1 &&\n"
        "\t\t\tSUSFS_IS_INODE_OPEN_REDIRECT_WITHOUT_UID_CHECK(path.dentry->d_inode))\n"
        "\t\t{\n"
        "\t\t\tfake_filename = susfs_open_redirect_spoof_do_sys_openat(path.dentry->d_inode);\n"
        "\t\t\tif (fake_filename && !IS_ERR(fake_filename)) {\n"
        "\t\t\t\tpath_put(&path);\n"
        "\t\t\t\trestore_nameidata();\n"
        "\t\t\t\tset_nameidata(nd, old_dfd, fake_filename);\n"
        "\t\t\t\terror = path_lookupat(nd, flags, &path);\n"
        "\t\t\t\tif (unlikely(error)) {\n"
        "\t\t\t\t\tputname(fake_filename);\n"
        "\t\t\t\t\treturn error;\n"
        "\t\t\t\t}\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "#endif // #ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT\n"
        "\t\taudit_inode(nd->name, path.dentry, 0);\n"
        "\t\terror = vfs_open(&path, file);\n"
        "\t\tpath_put(&path);\n"
        "\t}\n"
        "#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT\n"
        "\tif (fake_filename && !IS_ERR(fake_filename))\n"
        "\t\tputname(fake_filename);\n"
        "#endif // #ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT\n"
        "\treturn error;\n"
        "}\n"
    )
    src = replace_once(src, old_o_path, new_o_path, rel)

    # (c) deklarasi di awal path_openat (dipakai hunk #22-25 yang sudah masuk)
    old_po = (
        "static struct file *path_openat(struct nameidata *nd,\n"
        "\t\t\tconst struct open_flags *op, unsigned flags)\n"
        "{\n"
    )
    new_po = old_po + (
        "#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT\n"
        "\tint old_dfd = nd->dfd;\n"
        "\tstruct filename *fake_filename = NULL;\n"
        "#endif // #ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT\n"
    )
    return replace_once(src, old_po, new_po, rel)


# ------------------------------------------------------------------ cmdline.c
def fix_cmdline(src, rel):
    sig = "static int cmdline_proc_show(struct seq_file *m, void *v)\n{\n"
    decl = (
        "#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG\n"
        "extern struct static_key_false susfs_is_fake_cmdline_or_bootconfig_buffer_set;\n"
        "extern void susfs_spoof_cmdline_or_bootconfig(struct seq_file *m);\n"
        "#endif\n\n"
    )
    body = (
        "#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG\n"
        "\tif (static_branch_likely(&susfs_is_fake_cmdline_or_bootconfig_buffer_set)) {\n"
        "\t\tsusfs_spoof_cmdline_or_bootconfig(m);\n"
        "\t\tseq_putc(m, '\\n');\n"
        "\t\treturn 0;\n"
        "\t}\n"
        "#endif\n"
    )
    i = once(src, sig, rel)
    return src[:i] + decl + sig + body + src[i + len(sig):]


def patch(rel, fn, marker):
    p = ROOT / rel
    if not p.is_file():
        die(f"{rel} tidak ada")
    src = p.read_text()
    if marker in src:
        print(f"[skip] {rel}: sudah ada ({marker})")
        return
    p.write_text(fn(src, rel))
    print(f"[ok]   {rel}")


def main():
    # marker: kalau hunk ini ternyata sudah masuk lewat patch, jangan dobel
    patch("fs/namei.c", fix_namei, "restore_nameidata();\n\t\t\t\tset_nameidata(nd, old_dfd, fake_filename);\n\t\t\t\terror = path_lookupat(nd, flags, &path);\n\t\t\t\tif (unlikely(error)) {\n\t\t\t\t\tputname(fake_filename);\n\t\t\t\t\treturn error;\n\t\t\t\t}\n\t\t\t}\n\t\t}\n#endif // #ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT\n\t\taudit_inode(nd->name, path.dentry, 0);")
    patch("fs/proc/cmdline.c", fix_cmdline, "susfs_spoof_cmdline_or_bootconfig")
    print("[+] Fixup SUSFS selesai.")


if __name__ == "__main__":
    main()
