cd ~/Claude/rusty-linux-private
S=/tmp/claude-1000/-home-adam-Claude-rusty-linux-private/8899d7a1-0a09-44c7-84ec-a89db821638d/scratchpad
bash $S/verify.sh
echo "== EFI (OVMF) all 7, restored"
CODEC_BASE=build-efi BOOT_EFI=1 CODEC_DIR=build-codec-efi rig/codec-check.sh 2>&1 | grep -v objtool
echo VERIFY2-DONE
