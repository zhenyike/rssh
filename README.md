# rssh

#### 介绍
rssh是集密码管理、远程登录、远程执行命令于一体的工具。

#### 软件架构
参考sshpass源码，单可执行文件，运行时不依赖任何库

#### 安装教程
git clone https://github.com/zhenyike/rssh.git

clib 仅编译时需要，部署环境不需要  
cd rssh/clib  
make && make install  

cargo build --release --target=x86_64-unknown-linux-musl  

复制 target/x86_64-unknown-linux-musl/release/rssh 文件到 /usr/local/bin 目录  

#### 使用说明

首次使用请先初始化：rssh -f pwd flag，初始化密码为 init  
![初始化](https://images.gitee.com/uploads/images/2020/1104/114153_58423e3d_8136516.png "屏幕截图.png")

添加用户密码：rssh -c ip user password  
![添加用户密码](https://images.gitee.com/uploads/images/2020/1104/114252_2b0cb2d9_8136516.png "屏幕截图.png")

登录到远程服务器: rssh ip [user], user 默认为 root, ip 支持模糊匹配  
![登录](https://images.gitee.com/uploads/images/2020/1104/114421_5ea17744_8136516.png "屏幕截图.png")

远程执行命令：rssh -r ip user cmd  
![远程执行命令](https://images.gitee.com/uploads/images/2020/1104/114621_7388983a_8136516.png "屏幕截图.png")

不带任何参数可以查看说明  
![说明](https://images.gitee.com/uploads/images/2020/1109/101918_edf76e5e_8136516.png "屏幕截图.png")

#### 参与贡献


#### 特技

