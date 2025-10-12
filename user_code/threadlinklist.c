#include"user.h"

/*


void pushThreadLinkList(HANDLE threadPid){
    PThreadLinkListNode newNode=(PThreadLinkListNode)malloc(sizeof(ThreadLinkListNode));
    newNode->threadPid=threadPid;
    newNode->Flink=NULL;
    newNode->Blink=NULL;
    if(head==NULL){
        head=newNode;
        tail=newNode;
        return;
    }
    tail->Flink=newNode;
    newNode->Blink=tail;
    tail=newNode;
    return;
}
void freeThreadLinkList(){
    PThreadLinkListNode current=head;
    while (current!=NULL)
    {
        PThreadLinkListNode next=current->Flink;
        free(current);
        current=next;
    }
    head=NULL;
    tail=NULL;
}

*/
