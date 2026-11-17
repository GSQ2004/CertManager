#include <jni.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/xattr.h>
#include <sys/syscall.h>
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <cerrno>
#include <cstring>
#include <string>
#include <vector>
#include <regex>
#include <stdexcept>
#include <sstream>

namespace {
constexpr size_t MAX = 1048576;
struct Fd { int n; explicit Fd(int value): n(value) { if(n < 0) throw std::runtime_error(std::string("open: ")+strerror(errno)); }
 ~Fd(){ if(n>=0) close(n); } Fd(const Fd&)=delete; Fd& operator=(const Fd&)=delete; };
void need(bool ok, const std::string& msg) { if(!ok) throw std::runtime_error(msg+": "+strerror(errno)); }
std::string text(JNIEnv* e,jstring s){ const char* c=e->GetStringUTFChars(s,nullptr); std::string v(c); e->ReleaseStringUTFChars(s,c); return v; }
std::vector<unsigned char> bytes(JNIEnv* e,jbyteArray a){ std::vector<unsigned char> v(e->GetArrayLength(a)); e->GetByteArrayRegion(a,0,static_cast<jsize>(v.size()),reinterpret_cast<jbyte*>(v.data())); return v; }
void fail(JNIEnv* e,const std::exception& ex){ e->ThrowNew(e->FindClass("java/lang/IllegalStateException"),ex.what()); }
std::string name(const std::string& p){ need(getuid()==0,"Root required"); need(std::regex_match(p,std::regex("/data/misc/user/(0|[1-9][0-9]{0,5})/cacerts-added/[0-9a-f]{8}\\.[0-9]{1,4}")),"Unapproved CA path"); return p.substr(p.rfind('/')+1); }
int directory(const std::string& path){
 Fd root(open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC));
 int fd=dup(root.n); need(fd>=0,"dup");
 std::istringstream parts(path.substr(1)); std::string part;
 try { while(std::getline(parts,part,'/')) {
   need(!part.empty() && part!="." && part!="..","Invalid directory component");
   int next=openat(fd,part.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC); need(next>=0,"Unsafe/inaccessible parent"); close(fd); fd=next;
   struct stat s{}; need(fstat(fd,&s)==0,"Directory stat");
   need((s.st_uid==0 || s.st_uid==1000) && !(s.st_mode&S_IWOTH),"Untrusted directory owner/mode");
 } } catch(...) { close(fd); throw; } return fd;
}
std::string label(int fd){ char b[256]; ssize_t n=fgetxattr(fd,"security.selinux",b,sizeof(b)); need(n>0 && n<256,"SELinux context unavailable");
 if(b[n-1]=='\0') --n; std::string s(b,static_cast<size_t>(n)); need(std::regex_match(s,std::regex("[A-Za-z0-9_:,.-]{1,255}")),"Invalid SELinux context"); return s; }
bool same(const struct stat&a,const struct stat&b){ return a.st_dev==b.st_dev && a.st_ino==b.st_ino && a.st_size==b.st_size && a.st_uid==b.st_uid && a.st_gid==b.st_gid && a.st_mode==b.st_mode && a.st_mtim.tv_sec==b.st_mtim.tv_sec && a.st_mtim.tv_nsec==b.st_mtim.tv_nsec && a.st_ctim.tv_sec==b.st_ctim.tv_sec && a.st_ctim.tv_nsec==b.st_ctim.tv_nsec; }
std::vector<unsigned char> readFile(int fd){ struct stat before{},after{}; need(fstat(fd,&before)==0,"fstat");
 need(S_ISREG(before.st_mode) && before.st_nlink==1 && before.st_size>0 && before.st_size<=static_cast<off_t>(MAX),"Not a single-link bounded regular certificate");
 need((before.st_uid==0 || before.st_uid==1000) && !(before.st_mode & (S_IWGRP|S_IWOTH|0111|S_ISUID|S_ISGID|S_ISVTX)),"Unsafe certificate permissions");
 std::vector<unsigned char> data(static_cast<size_t>(before.st_size)); size_t done=0;
 while(done<data.size()){ ssize_t n=pread(fd,data.data()+done,data.size()-done,static_cast<off_t>(done)); need(n>0,"Certificate read"); done+=static_cast<size_t>(n); }
 need(fstat(fd,&after)==0 && same(before,after),"Certificate changed during read"); return data;
}
std::string header(int fd,int dir){ struct stat s{},d{}; need(fstat(fd,&s)==0&&fstat(dir,&d)==0,"Metadata stat");
 std::ostringstream o; o<<"1\t"<<s.st_dev<<'\t'<<s.st_ino<<'\t'<<s.st_uid<<'\t'<<s.st_gid<<'\t'<<(s.st_mode&0777)<<'\t'<<s.st_size<<'\t'<<s.st_mtim.tv_sec<<'\t'<<s.st_mtim.tv_nsec<<'\t'<<s.st_ctim.tv_sec<<'\t'<<s.st_ctim.tv_nsec<<'\t'<<d.st_dev<<'\t'<<d.st_ino<<'\t'<<label(fd); return o.str(); }
void noMount(int fd,const std::string& path){ struct statfs fs{}; need(fstatfs(fd,&fs)==0,"Filesystem identity");
 need(fs.f_type==0xEF53 || static_cast<unsigned long>(fs.f_type)==0xF2F52010UL,"Only ext4/f2fs traditional stores supported; overlays are read-only");
 Fd mounts(open("/proc/self/mountinfo",O_RDONLY|O_CLOEXEC)); std::string all; char b[8192]; ssize_t n;
 while((n=read(mounts.n,b,sizeof(b)))>0){ all.append(b,static_cast<size_t>(n)); need(all.size()<8*MAX,"Mount table limit"); }
 need(n==0,"Mount table read"); std::istringstream lines(all); std::string line;
 
 while(std::getline(lines,line)){ std::istringstream words(line); std::string w; for(int i=0;i<5;++i) words>>w;
  need(!(w.size()>5 && w.compare(0,6,"/data/")==0 && (w==path || (path.size()>w.size() && path.compare(0,w.size(),w)==0 && path[w.size()]=='/'))),"Certificate/profile bind mount detected; inspect Root modules"); }
}
void verifyDirectory(const std::string& path,int pinned){
 Fd current(directory(path)); struct stat a{},b{};
 need(fstat(current.n,&a)==0&&fstat(pinned,&b)==0&&a.st_dev==b.st_dev&&a.st_ino==b.st_ino,"Active directory was replaced");
}
void renameNoReplace(int from,const std::string& a,int to,const std::string& b){
 need(syscall(SYS_renameat2,from,a.c_str(),to,b.c_str(),1)==0,"Atomic no-replace rename (EXDEV is refused)");
}
std::vector<std::string> split(const std::string& s){ std::vector<std::string> v; std::istringstream in(s); std::string t; while(std::getline(in,t,'\t'))v.push_back(t); need(v.size()==14&&v[0]=="1","Invalid backup metadata"); return v; }

}
extern "C" JNIEXPORT jobjectArray JNICALL Java_com_certmanager_android_data_NativeGuard_snapshot(JNIEnv*e,jobject,jstring path){
 try { const auto p=text(e,path), n=name(p); Fd dir(directory(p.substr(0,p.rfind('/')))); noMount(dir.n,p);
  int opened=openat(dir.n,n.c_str(),O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
  if(opened<0 && errno==ENOENT) return nullptr; Fd fd(opened);
  auto raw=readFile(fd.n); auto h=header(fd.n,dir.n); need(readFile(fd.n)==raw && header(fd.n,dir.n)==h,"Snapshot changed"); struct stat a{},b{};
  need(fstat(fd.n,&a)==0 && fstatat(dir.n,n.c_str(),&b,AT_SYMLINK_NOFOLLOW)==0 && same(a,b),"Path replaced during snapshot");
  jobjectArray out=e->NewObjectArray(2,e->FindClass("[B"),nullptr);
  auto data=e->NewByteArray(static_cast<jsize>(raw.size())); e->SetByteArrayRegion(data,0,static_cast<jsize>(raw.size()),reinterpret_cast<jbyte*>(raw.data())); e->SetObjectArrayElement(out,1,data);
  auto meta=e->NewByteArray(static_cast<jsize>(h.size())); e->SetByteArrayRegion(meta,0,static_cast<jsize>(h.size()),reinterpret_cast<const jbyte*>(h.data())); e->SetObjectArrayElement(out,0,meta); return out;
 } catch(const std::exception&x){fail(e,x);return nullptr;}
}
extern "C" JNIEXPORT void JNICALL Java_com_certmanager_android_data_NativeGuard_move(JNIEnv*e,jobject,jstring path,jstring id,jstring expected,jbyteArray raw){
 try { auto p=text(e,path), n=name(p), token=text(e,id); need(std::regex_match(token,std::regex("[0-9a-f-]{36}")),"Invalid transaction ID");
  auto parent=p.substr(0,p.rfind('/')); auto user=parent.substr(0,parent.rfind('/'));
  Fd dir(directory(parent)); Fd userDir(directory(user)); noMount(dir.n,p);
  if(mkdirat(userDir.n,"certmanager-quarantine",0700)!=0) need(errno==EEXIST,"Quarantine creation");
  Fd q(openat(userDir.n,"certmanager-quarantine",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)); struct stat qs{},ds{};
  need(fstat(q.n,&qs)==0&&fstat(dir.n,&ds)==0&&qs.st_uid==0&&(qs.st_mode&0777)==0700&&qs.st_dev==ds.st_dev,"Untrusted/cross-filesystem quarantine");
  need(flock(q.n,LOCK_EX|LOCK_NB)==0,"Another Root operation is active");
  Fd fd(openat(dir.n,n.c_str(),O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC));
  auto original=bytes(e,raw); auto h=text(e,expected);
  need(readFile(fd.n)==original && header(fd.n,dir.n)==h,"Certificate bytes/identity/metadata changed since backup");
  struct stat a{},b{}; need(fstat(fd.n,&a)==0&&fstatat(dir.n,n.c_str(),&b,AT_SYMLINK_NOFOLLOW)==0&&same(a,b),"Pre-move path race");
  verifyDirectory(parent,dir.n); auto saved=token+".removed"; renameNoReplace(dir.n,n,q.n,saved);
  try {
   verifyDirectory(parent,dir.n);
   struct stat moved{}; need(fstatat(q.n,saved.c_str(),&moved,AT_SYMLINK_NOFOLLOW)==0 && moved.st_dev==a.st_dev && moved.st_ino==a.st_ino && moved.st_uid==a.st_uid && moved.st_gid==a.st_gid && moved.st_mode==a.st_mode,"Concurrent path replacement detected");
   need(readFile(fd.n)==original && label(fd.n)==split(h)[13],"Certificate changed during move");
  } catch(...) {
   // Preserve every byte. A raced object is returned only if the original name is still free.
   if(syscall(SYS_renameat2,q.n,saved.c_str(),dir.n,n.c_str(),1)!=0)
    throw std::runtime_error("Race: rollback blocked; object preserved in "+user+"/certmanager-quarantine/"+saved+"; backup retained");
   throw;
  }
  need(fsync(q.n)==0&&fsync(dir.n)==0,"Move applied but directory fsync failed; inspect quarantine and backup");
  struct stat remaining{}; need(fstatat(dir.n,n.c_str(),&remaining,AT_SYMLINK_NOFOLLOW)<0&&errno==ENOENT,"Certificate reappeared after move; do not remove again");
 } catch(const std::exception&x){fail(e,x);}
}
extern "C" JNIEXPORT void JNICALL Java_com_certmanager_android_data_NativeGuard_restore(JNIEnv*e,jobject,jstring path,jstring id,jstring metadata,jbyteArray raw){
 try { auto p=text(e,path), n=name(p), token=text(e,id); need(std::regex_match(token,std::regex("[0-9a-f-]{36}")),"Invalid transaction ID");
  auto fields=split(text(e,metadata)); auto data=bytes(e,raw); need(!data.empty()&&data.size()<=MAX,"Invalid certificate size");
  const auto parent=p.substr(0,p.rfind('/')); const auto user=parent.substr(0,parent.rfind('/'));
  Fd dir(directory(parent)); Fd userDir(directory(user)); noMount(dir.n,p);
  if(mkdirat(userDir.n,"certmanager-quarantine",0700)!=0) need(errno==EEXIST,"Quarantine creation");
  Fd q(openat(userDir.n,"certmanager-quarantine",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)); struct stat qs{},ds{};
  need(fstat(q.n,&qs)==0&&fstat(dir.n,&ds)==0&&qs.st_uid==0&&(qs.st_mode&0777)==0700&&qs.st_dev==ds.st_dev,"Untrusted/cross-filesystem restore staging");
  need(flock(q.n,LOCK_EX|LOCK_NB)==0,"Another Root operation is active");
  struct stat target{}; need(fstatat(dir.n,n.c_str(),&target,AT_SYMLINK_NOFOLLOW)<0&&errno==ENOENT,"Restore target exists/inaccessible");
  auto temp=token+".restore"; Fd fd(openat(q.n,temp.c_str(),O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600));
  bool published=false;
  try {
   size_t done=0; while(done<data.size()){ ssize_t count=write(fd.n,data.data()+done,data.size()-done); need(count>0,"Restore write"); done+=static_cast<size_t>(count); }
   auto uid=static_cast<uid_t>(std::stoul(fields[3])), gid=static_cast<gid_t>(std::stoul(fields[4])); auto mode=static_cast<mode_t>(std::stoul(fields[5]));
   need((uid==0||uid==1000) && !(mode&(S_IWGRP|S_IWOTH|0111|S_ISUID|S_ISGID|S_ISVTX)) && mode<=0777,"Unsafe metadata");
   need(fchown(fd.n,uid,gid)==0 && fchmod(fd.n,mode)==0,"Ownership/permission restore failed");
   need(fsetxattr(fd.n,"security.selinux",fields[13].c_str(),fields[13].size()+1,0)==0,"SELinux restore failed");
   struct stat s{}; need(fstat(fd.n,&s)==0&&s.st_uid==uid&&s.st_gid==gid&&(s.st_mode&0777)==mode&&label(fd.n)==fields[13]&&readFile(fd.n)==data,"Restored metadata/content mismatch");
   need(fsync(fd.n)==0,"Restore fsync failed");
   verifyDirectory(p.substr(0,p.rfind('/')),dir.n);
   renameNoReplace(q.n,temp,dir.n,n); published=true;
   verifyDirectory(p.substr(0,p.rfind('/')),dir.n);
   struct stat active{}; need(fstatat(dir.n,n.c_str(),&active,AT_SYMLINK_NOFOLLOW)==0&&active.st_ino==s.st_ino&&active.st_dev==s.st_dev,"Restore name changed; backup retained");
   need(fsync(dir.n)==0&&fsync(q.n)==0,"Restore published but directory fsync failed; backup retained");
  } catch(const std::exception& error) {
   if(!published) throw std::runtime_error(std::string(error.what())+"; inactive staging retained at "+user+"/certmanager-quarantine/"+temp+"; backup retained");
   throw;
  }
 } catch(const std::exception&x){fail(e,x);}
}
