#!/bin/sh

TARGET_SCRIPT="/usr/libexec/package-manager-call"

# 检查文件是否存在
if [ ! -f "$TARGET_SCRIPT" ]; then
    echo "❌ 错误：目标文件不存在，请修改脚本内的路径！"
    exit 1
fi

clear
echo "======================================"
echo "     APK 安装参数 --allow-untrusted 开关"
echo "======================================"
echo " 1 - 开启 （自动添加 --allow-untrusted）"
echo " 2 - 关闭 （恢复默认，删除参数）"
echo "======================================"
read -p "请输入选项 [1/2]：" num

case $num in
    1)
        sed -i 's/^[[:space:]]*action="add"$/                action="add --allow-untrusted"/' "$TARGET_SCRIPT"
        echo -e "\n✅ 已成功开启：apk add --allow-untrusted"
        ;;
    2)
        sed -i 's/^[[:space:]]*action="add --allow-untrusted"$/                action="add"/' "$TARGET_SCRIPT"
        echo -e "\n✅ 已成功关闭：恢复为 apk add"
        ;;
    *)
        echo -e "\n❌ 输入错误，请输入 1 或 2"
        ;;
esac
