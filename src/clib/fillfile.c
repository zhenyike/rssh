#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>

#define FILE_MODE 0700

/* 文件尾结构体 */
typedef struct _FILE_TAIL {
    unsigned long pos;          // 加密信息偏移
    unsigned long size;         // 加密信息大小
} FILE_TAIL;

/* 获取文件大小 */
unsigned long get_file_size(const char *path) {
    unsigned long filesize = -1;
    struct stat statbuff;
    if (stat(path, &statbuff) < 0) {
        return filesize;
    } else {
        filesize = statbuff.st_size;
    }
    return filesize;
}

/* 复制指定长度文件 */
int copy_file(const char *old_file, const char *new_file, unsigned long fill_len) {

    int fd_old = open(old_file, O_RDONLY, FILE_MODE);
    int fd_new = open(new_file, O_WRONLY | O_CREAT, FILE_MODE);
    char *buff = (char *) malloc(sizeof(char) * fill_len);

    int re = read(fd_old, buff, fill_len);
    int wr = write(fd_new, buff, fill_len);

    close(fd_new);
    close(fd_old);

    free(buff);
    return wr;
}

/* 追加写文件 */
int append_file(const char *file_name, char *buff) {

    int fd = open(file_name, O_WRONLY | O_APPEND, FILE_MODE);

    int buff_len = strlen(buff);
    int re = write(fd, buff, buff_len);
    close(fd);
    return re;
}

/* 从文件读取 FILE_TAIL 结构体, 返回结构体指针, 需要接收者释放 */
FILE_TAIL *read_tail(const char *file_name) {

    int fd = open(file_name, O_RDONLY, FILE_MODE);
    FILE_TAIL *tail = (FILE_TAIL *) malloc(sizeof(FILE_TAIL));
    unsigned long index = get_file_size(file_name) - sizeof(FILE_TAIL);         // 结构体偏移 = 文件总大小 - 结构体大小
    lseek(fd, index, SEEK_SET);
    read(fd, tail, sizeof(FILE_TAIL));
    close(fd);
    return tail;
}

/********************************************************************************************************* 对外函数 */
/* 初始化文件 填充空白与尾部
 * 文件名: file_name.bak
 * 
 * file_name: 文件名
 * size:      填充空白大小
 * pos:       0: 未初始化过, 1: 已经初始化过, 重新初始化
 */
int init_file(const char *file_name, const char *data, unsigned long size, int pos) {

    char *bak = ".bak";
    char *file_bak = (char *) malloc(strlen(file_name) + strlen(bak));
    sprintf(file_bak, "%s%s", file_name, bak);

    unsigned long fsize = get_file_size(file_name);
    if (pos == 1) {
        FILE_TAIL *t = read_tail(file_name);
        fsize = t->pos - 20;
        free(t);
    }
    // 复制文件
    copy_file(file_name, file_bak, fsize);

    // 填充空白
    char *cfill = (char *) malloc(sizeof(char *) * size);
    memset(cfill, 0, size);

    int fd = open(file_bak, O_APPEND | O_WRONLY, FILE_MODE);
    int wr = write(fd, cfill, size);

    // 写入 data
    wr = write(fd, data, strlen(data));
    close(fd);

    // 写入 TAIL 结构体
    FILE_TAIL tail;
    tail.pos = get_file_size(file_bak) - wr;
    tail.size = wr;

    fd = open(file_bak, O_WRONLY | O_APPEND, FILE_MODE);
    int re = write(fd, (FILE_TAIL *) &tail, sizeof(FILE_TAIL));

    close(fd);
    if (re == -1) {
         return 1;
    } else {
         return 0;
    }
}

typedef struct __RE {
    int size;
    char *value;
} RE;

/* 读取密码信息 */
RE read_info(const char *file_name) {

    FILE_TAIL *tail = read_tail(file_name);

    char *buff = (char *) malloc(sizeof(char) * tail->size + 1);    // 加密信息缓冲区
    int fd = open(file_name, O_RDONLY, FILE_MODE);
    lseek(fd, tail->pos, SEEK_SET);
    int re_size = read(fd, buff, tail->size);
    close(fd);

    free(tail);
    RE re;
    re.size = re_size;
    re.value = buff;
    re.value[re.size] = '\0';       // 截断字符串，防止溢出
    return re;
}

/* 修改密码信息 */
int write_info(const char *file_name, char *str) {

    char *bak = ".bak";
    char *file_bak = (char *) malloc(strlen(file_name) + strlen(bak));
    sprintf(file_bak, "%s%s", file_name, bak);


    FILE_TAIL *tail = read_tail(file_name);
    copy_file(file_name, file_bak, tail->pos);

    int re = append_file(file_bak, str);
    tail->size = re;

    int fd = open(file_bak, O_WRONLY | O_APPEND, FILE_MODE);

    re = write(fd, tail, sizeof(FILE_TAIL));
    free(tail);

    close(fd);
    
    if (re == -1) {
         return 1;
    } else {
         return 0;
    }
}
