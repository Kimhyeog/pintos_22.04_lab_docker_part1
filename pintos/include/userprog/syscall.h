#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);
// 파일 시스템 락 사용
/* [추가] extern을 붙여서 "이 변수는 어딘가에 정의되어 있다"고 알림 */
extern struct lock filesys_lock;

#endif /* userprog/syscall.h */
