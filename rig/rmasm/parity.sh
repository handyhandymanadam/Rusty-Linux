cd "$(dirname "$0")/../.."
source ./kbuild-env.sh
b=build-fast; D=$PWD/tmp-rmasm/par; rm -rf $D; mkdir -p $D
kmake O="$PWD/$b" -j4 >/dev/null 2>&1; echo "rust-stub build rc=$?"
python3 rig/stubc-parity/corrupt.py $b/arch/x86/boot/bzImage $b/arch/x86/boot/compressed/vmlinux $D/bad-rust.bz 14
rm -f $b/arch/x86/boot/compressed/*.o $b/arch/x86/boot/compressed/vmlinux
kmake O="$PWD/$b" -j4 boot_rust_ok= >/dev/null 2>&1; echo "C-stub build rc=$?"
echo "C-stub rust syms: $(nm $b/arch/x86/boot/compressed/vmlinux | grep -cE '_rs|rust_')"
python3 rig/stubc-parity/corrupt.py $b/arch/x86/boot/bzImage $b/arch/x86/boot/compressed/vmlinux $D/bad-c.bz 14
rig/stubc-parity/matrix.sh $D; echo "matrix rc=$?"
rm -f $b/arch/x86/boot/compressed/*.o $b/arch/x86/boot/compressed/vmlinux
kmake O="$PWD/$b" -j4 >/dev/null 2>&1; echo "restored build rc=$?"
echo PARITY-DONE
