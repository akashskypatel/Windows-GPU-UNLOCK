/* GPL-2.0-only. Read-only GA10x capture for the 3070 Ti headless port.
 * PCI config reads, BAR0 Mem.Read, PROM hash, loaded-image dumps only. */
#include <Uefi.h>
#include <Protocol/PciIo.h>
#include <Protocol/DriverBinding.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/DevicePath.h>
#include <Protocol/GraphicsOutput.h>
#include <Protocol/SimpleFileSystem.h>
#include <IndustryStandard/Acpi.h>
#include "../unlock/sha256.h"
#include "probe.h"
#include "probe-pin.h"
#ifdef GU_PROBE_PARENT_BASELINE
#include "probe-parent.h"
#if !defined(GU_PROBE_GENERIC) || !defined(GU_DIAGNOSTIC_ONLY) || !defined(GU_DIAGNOSTIC_PROBE) || defined(GU_FULL_UNLOCK) || defined(GU_EXPERIMENTAL_3090)
#error Parent baseline requires the generic read-only probe
#endif
#endif
#include "../unlock/machine-profile.h"

#if defined(GU_NVGOP_DRIVER_EVIDENCE) && (!defined(GU_PROBE_GENERIC) || !defined(GU_DIAGNOSTIC_ONLY) || !defined(GU_DIAGNOSTIC_PROBE) || defined(GU_FULL_UNLOCK) || defined(GU_EXPERIMENTAL_3090))
#error NVIDIA driver evidence capture must be a generic, read-only diagnostic build
#endif
#if defined(GU_NVGOP_CONTEXT_EVIDENCE) && (!defined(GU_NVGOP_DRIVER_EVIDENCE) || !defined(GU_PROBE_GENERIC) || !defined(GU_DIAGNOSTIC_ONLY) || !defined(GU_DIAGNOSTIC_PROBE) || defined(GU_FULL_UNLOCK) || defined(GU_EXPERIMENTAL_3090))
#error NVIDIA context snapshot requires the read-only driver-evidence probe
#endif
#if defined(GU_PROBE_DUMP_PROM) && (!defined(GU_DIAGNOSTIC_ONLY) || !defined(GU_DIAGNOSTIC_PROBE) || !defined(GU_USB_MEDIA) || defined(GU_FULL_UNLOCK) || defined(GU_EXPERIMENTAL_3090))
#error GU_PROBE_DUMP_PROM is only for the observation-only diagnostic image
#endif
#if defined(GU_PROBE_GENERIC) || defined(GU_PROBE_DUMP_PROM) || defined(GU_PROFILE_H610M_3060) || defined(GU_PROFILE_PROBE_H610M_3060) || (defined(GU_DIAGNOSTIC_ONLY) && defined(GU_USB_MEDIA))
#define GU_CHECKED_PROBE 1
#endif
#if defined(GU_NVGOP_DRIVER_EVIDENCE) || defined(GU_PROBE_DUMP_PROM) || defined(GU_PROFILE_H610M_3060) || defined(GU_PROFILE_PROBE_H610M_3060) || (defined(GU_DIAGNOSTIC_ONLY) && defined(GU_USB_MEDIA))
#define GU_PROBE_PRESERVE_CAPTURE 1
#endif
/* Auto discovery is restricted to the profile-less read-only probe. An explicit
 * bus remains a constraint, never a fallback to a different target. */
#if defined(GU_PROBE_AUTO_BUS) && (!defined(GU_PROBE_GENERIC) || !defined(GU_DIAGNOSTIC_ONLY) || !defined(GU_DIAGNOSTIC_PROBE) || defined(GU_PROBE_BUS) || defined(GU_FULL_UNLOCK) || defined(GU_EXPERIMENTAL_3090))
#error GU_PROBE_AUTO_BUS requires an unconstrained generic read-only diagnostic probe
#endif
#ifndef GU_PROBE_BUS
#define GU_PROBE_BUS 1U
#endif
#if GU_PROBE_BUS < 1U || GU_PROBE_BUS > 255U
#error GU_PROBE_BUS must be between 1 and 255
#endif
#if defined(GU_PROBE_BUS) && !defined(GU_DIAGNOSTIC_ONLY) && GU_PROBE_BUS != 1U
#error A non-default GU_PROBE_BUS is only for the read-only diagnostic probe
#endif

VOID Text(CAPTURE *c,const char *s);
VOID Hex(CAPTURE *c,UINT64 v,UINTN digits);
VOID End(CAPTURE *c);
VOID Problem(CAPTURE *c,const char *where,EFI_STATUS s);

#ifdef GU_PROBE_GENERIC
/* Profile-less probe for a new machine: every NVIDIA display controller
 * (vendor 0x10de, class 0x03) is recorded. Read-only diagnostic builds only. */
#if !defined(GU_DIAGNOSTIC_ONLY) || !defined(GU_DIAGNOSTIC_PROBE) || defined(GU_FULL_UNLOCK) || defined(GU_EXPERIMENTAL_3090)
#error GU_PROBE_GENERIC is a read-only diagnostic build only
#endif
static BOOLEAN ProbeTarget(EFI_PCI_IO_PROTOCOL *io,UINT32 id) {
  UINT32 cls=0;
  return (id&0xffffU)==0x10deU && io->Pci.Read(io,EfiPciIoWidthUint32,8,1,&cls)==EFI_SUCCESS && (cls>>24)==3;
}
#else
static BOOLEAN ProbeTarget(EFI_PCI_IO_PROTOCOL *io,UINT32 id) {(void)io;return id==GU_BOARD_ID;}
#endif
static EFI_GUID PciGuidL=EFI_PCI_IO_PROTOCOL_GUID;
static EFI_GUID BindGuidL=EFI_DRIVER_BINDING_PROTOCOL_GUID;
static EFI_GUID ImgGuidL=EFI_LOADED_IMAGE_PROTOCOL_GUID;
static EFI_GUID PathGuidL=EFI_DEVICE_PATH_PROTOCOL_GUID;
static EFI_GUID GopGuidL=EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID;
static EFI_SYSTEM_TABLE *SysT;
static UINTN DumpIndex;
static CHAR16 ImgPrefix[]=L"\\RTX3090-UNLOCK\\IMG";

#ifdef GU_PROBE_PRESERVE_CAPTURE
/* No CREATE flag until absence was confirmed. Never replace an earlier capture.
 * Repeated boots require the operator to archive the complete capture set. */
static BOOLEAN NewDump(CAPTURE *c,EFI_FILE_PROTOCOL *root,CHAR16 *name) {
  EFI_FILE_PROTOCOL *prior=NULL;
  EFI_STATUS s=root->Open(root,&prior,name,EFI_FILE_MODE_READ,0);
  if(s==EFI_NOT_FOUND && !prior)return TRUE;
  if(s==EFI_SUCCESS && prior && prior!=root && prior->Close)prior->Close(prior);
  Problem(c,"dump-exists-or-unreadable",s==EFI_SUCCESS?EFI_ALREADY_STARTED:s);
  return FALSE;
}
#endif

static VOID PH(CAPTURE *c,const char *s,UINT64 v){Text(c,s);Hex(c,v,16);End(c);}

static VOID DumpPath(CAPTURE *c,const EFI_DEVICE_PATH_PROTOCOL *p,UINTN bound) {
  if(!p){Text(c,"img path absent");End(c);return;}
  UINTN at=0;
  for(UINTN nodes=0;nodes<64 && at+4<=bound;nodes++) {
    const UINT8 *b=(const VOID *)p;UINTN n=b[2]+((UINTN)b[3]<<8);
    if(n<4||n>bound-at){Problem(c,"img-path-len",EFI_COMPROMISED_DATA);return;}
    Text(c,"img-path-node raw=");for(UINTN j=0;j<n;j++)Hex(c,b[j],2);End(c);
    at+=n;p=(const VOID *)(b+n);
    if(b[0]==END_DEVICE_PATH_TYPE&&b[1]==END_ENTIRE_DEVICE_PATH_SUBTYPE)return;
  }
}

static VOID DumpImage(CAPTURE *c,EFI_FILE_PROTOCOL *root,EFI_HANDLE img) {
  EFI_LOADED_IMAGE_PROTOCOL *li=NULL;
  if(SysT->BootServices->HandleProtocol(img,&ImgGuidL,(VOID **)&li)!=EFI_SUCCESS||!li)return;
  PH(c,"img base=0x",(UINTN)li->ImageBase);
  PH(c,"img size=0x",li->ImageSize);
  PH(c,"img code-type=0x",li->ImageCodeType);
  DumpPath(c,li->FilePath,4096);
  if(!li->ImageBase||!li->ImageSize||li->ImageSize>4U*1024U*1024U)return;
  if(DumpIndex>=100){Problem(c,"img-count",EFI_BAD_BUFFER_SIZE);return;}
  CHAR16 name[40];UINTN i=DumpIndex++,k=0;
  Text(c,"img dump index=");Hex(c,i,4);End(c);
  while(ImgPrefix[k])name[k]=ImgPrefix[k],k++;
  name[k++]=(CHAR16)('0'+(i/10)%10);name[k++]=(CHAR16)('0'+i%10);
  name[k++]='.';name[k++]='B';name[k++]='I';name[k++]='N';name[k]=0;
#ifdef GU_PROBE_PRESERVE_CAPTURE
  if(!NewDump(c,root,name))return;
#endif
  EFI_FILE_PROTOCOL *f=NULL;
  EFI_STATUS s=root->Open(root,&f,name,EFI_FILE_MODE_READ|EFI_FILE_MODE_WRITE|EFI_FILE_MODE_CREATE,0);
  if(s!=EFI_SUCCESS||!f){Problem(c,"img-open",s);return;}
  if(!f->Write || !f->Close){Problem(c,"img-file-methods",EFI_UNSUPPORTED);return;}
  UINTN n=li->ImageSize;s=f->Write(f,&n,li->ImageBase);
  if(s!=EFI_SUCCESS||n!=li->ImageSize)Problem(c,"img-write",s==EFI_SUCCESS?EFI_END_OF_FILE:s);
  if(!f->Flush || f->Flush(f)!=EFI_SUCCESS)Problem(c,"img-flush",EFI_DEVICE_ERROR);
  if(f->Close(f)!=EFI_SUCCESS)Problem(c,"img-close",EFI_DEVICE_ERROR);
}

static VOID ProbeCaps(CAPTURE *c,EFI_PCI_IO_PROTOCOL *io) {
  UINT32 v=0;UINT8 off=0;
  if(io->Pci.Read(io,EfiPciIoWidthUint8,0x34,1,&off)!=EFI_SUCCESS){Problem(c,"cap-ptr",EFI_DEVICE_ERROR);return;}
  for(UINTN i=0;i<48 && off>=0x40 && !(off&3);i++) {
    UINT8 id=0,next=0;
    if(io->Pci.Read(io,EfiPciIoWidthUint8,off,1,&id)!=EFI_SUCCESS)break;
    if(io->Pci.Read(io,EfiPciIoWidthUint8,off+1,1,&next)!=EFI_SUCCESS)break;
    PH(c,"cap off=0x",off);PH(c,"cap id=0x",id);PH(c,"cap next=0x",next);
    if(io->Pci.Read(io,EfiPciIoWidthUint32,off,1,&v)==EFI_SUCCESS){PH(c,"cap dword0=0x",v);}
    if(io->Pci.Read(io,EfiPciIoWidthUint32,off+4,1,&v)==EFI_SUCCESS){PH(c,"cap dword1=0x",v);}
    if(io->Pci.Read(io,EfiPciIoWidthUint32,off+8,1,&v)==EFI_SUCCESS){PH(c,"cap dword2=0x",v);}
    if(id==0x10){
      if(io->Pci.Read(io,EfiPciIoWidthUint32,off+12,1,&v)==EFI_SUCCESS)PH(c,"pcie dword3=0x",v);
      if(io->Pci.Read(io,EfiPciIoWidthUint32,off+16,1,&v)==EFI_SUCCESS)PH(c,"pcie dword4=0x",v);
      if(io->Pci.Read(io,EfiPciIoWidthUint32,off+20,1,&v)==EFI_SUCCESS)PH(c,"pcie dword5=0x",v);
    }
    if(!next||next==off)break;off=next;
  }
}

/* Host-test fixture only: the same PROM bytes that were hashed, never parsed here. */
#if defined(GU_PROBE_GENERIC) || defined(GU_PROBE_DUMP_PROM)
static VOID DumpProm(CAPTURE *c,EFI_FILE_PROTOCOL *root,UINT8 *page) {
#ifdef GU_PROBE_PRESERVE_CAPTURE
  if(!NewDump(c,root,L"\\RTX3090-UNLOCK\\PROM.BIN"))return;
#endif
  EFI_FILE_PROTOCOL *f=NULL;
  EFI_STATUS s=root->Open(root,&f,L"\\RTX3090-UNLOCK\\PROM.BIN",EFI_FILE_MODE_READ|EFI_FILE_MODE_WRITE|EFI_FILE_MODE_CREATE,0);
  if(s!=EFI_SUCCESS||!f){Problem(c,"prom-open",s);return;}
  if(!f->Write || !f->Close){Problem(c,"prom-file-methods",EFI_UNSUPPORTED);return;}
  UINTN n=0x100000;s=f->Write(f,&n,page);
  if(s!=EFI_SUCCESS||n!=0x100000)Problem(c,"prom-write",s==EFI_SUCCESS?EFI_END_OF_FILE:s);
  else{Text(c,"prom dump=PROM.BIN");End(c);}
  if(!f->Flush || f->Flush(f)!=EFI_SUCCESS)Problem(c,"prom-flush",EFI_DEVICE_ERROR);
  if(f->Close(f)!=EFI_SUCCESS)Problem(c,"prom-close",EFI_DEVICE_ERROR);
}
#endif

#ifdef GU_CHECKED_PROBE
/* Inventory never implies permission to read another GPU's register map.
 * Generic reads accept the reviewed GA102, GA104 and GA106 identities;
 * named probes pin their own
 * PCI/subsystem and require the same 16 MiB, MEM1/BME0 resource envelope.
 * All allocation/protocol calls finish before the final identity/config recheck. */
static BOOLEAN ProbeEnvelope(CAPTURE *c,EFI_PCI_IO_PROTOCOL *io,const UINT32 *cfg) {
#ifdef GU_PROBE_GENERIC
  BOOLEAN identity=cfg[0]==0x220410deU || cfg[0]==0x220310deU ||
    cfg[0]==0x248710deU || cfg[0]==0x250410deU || cfg[0]==0x248410deU || cfg[0]==0x24c910deU || cfg[0]==0x220a10deU;
#else
  BOOLEAN identity=cfg[0]==GU_BOARD_ID && cfg[11]==GU_BOARD_SUBSYSTEM;
#ifdef GU_BAR0_BASE
  if(cfg[4]!=(UINT32)GU_BAR0_BASE)identity=FALSE;
#endif
#endif
  if(!identity || cfg[2]!=0x030000a1U ||
     (cfg[1]&6U)!=2U || !cfg[4] || (cfg[4]&0xffffffU) || !io->GetBarAttributes || !io->Mem.Read)return FALSE;
  VOID *raw=NULL;
  EFI_FREE_POOL release=c->Table->BootServices->FreePool;
  if(!release)return FALSE;
  EFI_STATUS s=io->GetBarAttributes(io,0,NULL,&raw);
  BOOLEAN good=FALSE;
  if(s==EFI_SUCCESS && raw) {
    const EFI_ACPI_ADDRESS_SPACE_DESCRIPTOR *d=raw;
    const UINT8 *end=(const UINT8 *)(d+1);
    good=d->Desc==ACPI_ADDRESS_SPACE_DESCRIPTOR && d->Len==sizeof(*d)-3 && !d->ResType &&
      d->AddrSpaceGranularity==32 && d->AddrRangeMin==cfg[4] && d->AddrLen==0x1000000 &&
      !d->AddrTranslationOffset && (d->AddrRangeMax==(UINT64)cfg[4]+0xffffff || d->AddrRangeMax==0xffffff) &&
      end[0]==ACPI_END_TAG_DESCRIPTOR;
    if(good) {
      UINT8 sum=0;for(UINTN j=0;j<sizeof(*d)+2;j++)sum=(UINT8)(sum+((const UINT8 *)d)[j]);
      if(end[1] && sum)good=FALSE;
    }
    if(good) {
      UINT8 observed[sizeof(*d)+2];
      for(UINTN j=0;j<sizeof(observed);j++)observed[j]=((const UINT8 *)d)[j];
      Text(c,"pci-bar0-resource raw=");
      for(UINTN j=0;j<sizeof(observed);j++)Hex(c,observed[j],2);
      End(c);
    }
  }
  if(raw && release(raw)!=EFI_SUCCESS)good=FALSE;
  return good;
}
static BOOLEAN ProbeUnchanged(CAPTURE *c,EFI_HANDLE handle,EFI_PCI_IO_PROTOCOL *io,const UINT32 *cfg,UINTN expectedSegment,UINTN expectedBus) {
  EFI_PCI_IO_PROTOCOL *current=NULL;UINTN seg=~(UINTN)0,bus=~(UINTN)0,dev=~(UINTN)0,fun=~(UINTN)0;UINT32 now[64];
  /* Every byte differs from its expected value; successful short output cannot
   * reuse a preceding snapshot or accidentally match a zero BDF field. */
  for(UINTN j=0;j<64;j++)now[j]=~cfg[j];
  if(!io || !c->Table->BootServices || !c->Table->BootServices->HandleProtocol ||
     c->Table->BootServices->HandleProtocol(handle,&PciGuidL,(VOID **)&current)!=EFI_SUCCESS || current!=io ||
     !io->GetLocation || io->GetLocation(io,&seg,&bus,&dev,&fun)!=EFI_SUCCESS || seg!=expectedSegment || bus!=expectedBus || dev || fun ||
     !io->Pci.Read || io->Pci.Read(io,EfiPciIoWidthUint32,0,64,now)!=EFI_SUCCESS)return FALSE;
  for(UINTN j=0;j<64;j++)if(now[j]!=cfg[j])return FALSE;
  return TRUE;
}
#endif
#if defined(GU_NVGOP_DRIVER_EVIDENCE)
/* Optional, exact-machine read-only evidence. No MMIO, image execution, Stop,
 * DisconnectController, or device state changes. Never dump an unbound image. */
typedef struct {
  EFI_HANDLE Handle;
  EFI_PCI_IO_PROTOCOL *Io;
  UINTN Segment,Bus;
  UINT32 Config[64];
} GU_NV_EVIDENCE;

static BOOLEAN NvEvidenceName(const EFI_DEVICE_PATH_PROTOCOL *p,const CHAR16 *expected) {
  if(!p || p->Type!=MEDIA_DEVICE_PATH || p->SubType!=MEDIA_FILEPATH_DP)return FALSE;
  const UINT8 *bytes=(const UINT8 *)p;
  UINTN len=(UINTN)bytes[2]+((UINTN)bytes[3]<<8),namesize=0;
  while(expected[namesize] && namesize<32)namesize++;
  if(namesize>=32 || len!=4+(namesize+1)*2)return FALSE;
  for(UINTN i=0;i<=namesize;i++)
    if(bytes[4+i*2]!=(UINT8)expected[i] || bytes[5+i*2]!=(UINT8)(expected[i]>>8))return FALSE;
  const UINT8 *end=bytes+len;
  return end[0]==END_DEVICE_PATH_TYPE && end[1]==END_ENTIRE_DEVICE_PATH_SUBTYPE &&
    end[2]==4 && end[3]==0;
}


#ifdef GU_NVGOP_CONTEXT_EVIDENCE
/* Observe only the two exact loaded code revisions from DIAG08. These private
 * offsets are not portable across NVIDIA GOP versions. No vendor methods,
 * MMIO, driver detach, or reset are invoked. */
static const UINT8 NvText3080[32]={0x61,0x5b,0x37,0xa7,0x08,0xb1,0x89,0x4e,0x18,0xd7,0xfa,0x60,0xcf,0xcd,0xac,0xaa,0x4d,0x8b,0x59,0x88,0x63,0xa1,0x0b,0x81,0x03,0xd2,0x31,0xa5,0x95,0x84,0x7b,0x2b};
static const UINT8 NvText4090[32]={0x77,0x63,0x29,0x02,0xf0,0xce,0xb0,0xba,0x28,0x48,0x20,0x0f,0x39,0x6a,0xb6,0x1e,0xac,0xd7,0x91,0x0e,0x9c,0xce,0x7c,0x53,0x5f,0x65,0xd6,0xcd,0xbe,0x2b,0x6c,0x32};
static EFI_GUID NvPrivateGuid={0xfe47349a,0x7f0d,0x4641,{0x82,0x2b,0x34,0xba,0xa2,0x8e,0xcd,0xd0}};

/* Bounded progress to USB diagnostic AND visible AMD preboot console.
 * The full handle graph remains file-only to avoid flooding the display. */
static VOID NvCtxField(CAPTURE *c,UINT32 id,const char *field,UINTN value) {
  Text(c,"nvgop-context-v1 pci-id=0x");Hex(c,id,8);
  Text(c," ");Text(c,field);Text(c,"=0x");Hex(c,value,16);End(c);
  if(!SysT || !SysT->ConOut || !SysT->ConOut->OutputString)return;
  CHAR16 line[144];UINTN n=0;
  const char *prefix=id==0x268410deU?"NVGOP RTX4090 ":"NVGOP RTX3080 ";
  while(*prefix && n<48)line[n++]=(CHAR16)(UINT8)*prefix++;
  while(*field && n<90)line[n++]=(CHAR16)(UINT8)*field++;
  line[n++]='=';line[n++]='0';line[n++]='x';
  for(int i=15;i>=0;i--)line[n++]=(CHAR16)"0123456789abcdef"[(value>>(i*4))&15U];
  line[n++]='\r';line[n++]='\n';line[n]=0;
  (void)SysT->ConOut->OutputString(SysT->ConOut,line);
}

/* Require the entire bounded read to be inside ONE BootServicesData region.
 * Firmware memory-map validation reduces risk but does not prove live object
 * lifetime or protect against concurrent changes by firmware callbacks. */
static BOOLEAN NvCtxHeap(const EFI_MEMORY_DESCRIPTOR *map,UINTN used,UINTN step,
                         UINTN address,UINTN bytes) {
  if(!address || (address&7U) || !bytes || bytes>0x1000U ||
     address>~(UINTN)0-bytes || step<sizeof(EFI_MEMORY_DESCRIPTOR))return FALSE;
  for(UINTN off=0;off<=used && used-off>=step;off+=step) {
    const EFI_MEMORY_DESCRIPTOR *d=(const VOID *)((const UINT8 *)map+off);
    if(d->Type!=EfiBootServicesData || d->NumberOfPages>~(UINT64)0/4096U)continue;
    UINT64 start=d->PhysicalStart,span=d->NumberOfPages*4096U;
    if(start>~(UINT64)0-span)continue;
    UINT64 end=start+span;
    if((UINT64)address>=start && (UINT64)address<=end &&
       (UINT64)bytes<=end-(UINT64)address)return TRUE;
  }
  return FALSE;
}

/* Called only after exact PCI identity, driver binding and loaded-image
 * provenance have been verified by NvEvidenceImage. No arbitrary scan. */
static VOID NvCtxSnapshot(CAPTURE *c,const GU_NV_EVIDENCE *v,
                          const EFI_LOADED_IMAGE_PROTOCOL *image) {
  UINT32 id=v->Config[0];
  BOOLEAN is4090=id==0x268410deU;
  UINTN textSize=is4090?137711U:134451U;
  UINTN vtableRva=is4090?0x22270U:0x215b0U;
  const UINT8 *expected=is4090?NvText4090:NvText3080;
  EFI_BOOT_SERVICES *bs=c->Table->BootServices;
  EFI_MEMORY_DESCRIPTOR *map=NULL;
  UINTN used=0,step=0;
  EFI_STATUS failure=EFI_NOT_READY;
  BOOLEAN ok=FALSE;
  UINT8 digest[32];
  NvCtxField(c,id,"begin",1);
  if(!bs || !bs->HandleProtocol || !bs->GetMemoryMap || !bs->AllocatePool || !bs->FreePool ||
     !image || !image->ImageBase || image->ImageSize<0x280U+textSize)goto done;
  GuSha256((UINT8 *)image->ImageBase+0x280U,textSize,digest);
  BOOLEAN match=TRUE;
  for(UINTN i=0;i<32;i++)if(digest[i]!=expected[i])match=FALSE;
  NvCtxField(c,id,"text_hash_match",match?1:0);
  if(!match){failure=EFI_UNSUPPORTED;goto done;}
  VOID *context=NULL;
  EFI_STATUS s=bs->HandleProtocol(v->Handle,&NvPrivateGuid,&context);
  NvCtxField(c,id,"protocol_status",s);
  if(s!=EFI_SUCCESS || !context){failure=s==EFI_SUCCESS?EFI_NOT_FOUND:s;goto done;}
  /* A fixed initial map allocation avoids relying on GetMemoryMap(NULL).
   * Repeat at most three times if memory-map growth requires more space. */
  UINTN capacity=65536U;
  for(UINTN attempt=0;attempt<3;attempt++) {
    s=bs->AllocatePool(EfiBootServicesData,capacity,(VOID **)&map);
    if(s!=EFI_SUCCESS || !map){failure=s==EFI_SUCCESS?EFI_OUT_OF_RESOURCES:s;goto done;}
    used=capacity;
    UINTN key=0;UINT32 version=0;
    s=bs->GetMemoryMap(&used,map,&key,&step,&version);
    if(s==EFI_SUCCESS)break;
    EFI_STATUS released=bs->FreePool(map);map=NULL;
    if(released!=EFI_SUCCESS){failure=released;goto done;}
    if(s!=EFI_BUFFER_TOO_SMALL || !step || step>1024U ||
       used>1024U*1024U || used>1024U*1024U-16U*step){failure=s;goto done;}
    capacity=used+16U*step;
  }
  NvCtxField(c,id,"memory_map_status",s);
  if(s!=EFI_SUCCESS || !map || step<sizeof(EFI_MEMORY_DESCRIPTOR) || step>1024U ||
     !used || used>1024U*1024U || used%step){failure=EFI_COMPROMISED_DATA;goto done;}
  UINTN cp=(UINTN)context;
  NvCtxField(c,id,"context",cp);
  if(!NvCtxHeap(map,used,step,cp,0xa0U)){failure=EFI_COMPROMISED_DATA;goto done;}
  UINTN handle=*(volatile const UINTN *)(cp+0x28U);
  UINTN pciIo=*(volatile const UINTN *)(cp+0x30U);
  NvCtxField(c,id,"context_handle",handle);
  NvCtxField(c,id,"context_pci_io",pciIo);
  if(handle!=(UINTN)v->Handle || pciIo!=(UINTN)v->Io){
    failure=EFI_COMPROMISED_DATA;goto done;
  }
  NvCtxField(c,id,"reset_flag_98",*(volatile const UINT8 *)(cp+0x98U));
  UINTN factory=*(volatile const UINTN *)(cp+0x38U);
  UINTN auxiliary=*(volatile const UINTN *)(cp+0x40U);
  UINTN device=*(volatile const UINTN *)(cp+0x48U);
  UINTN allocation=*(volatile const UINTN *)(cp+0x68U);
  NvCtxField(c,id,"factory",factory);
  NvCtxField(c,id,"auxiliary",auxiliary);
  NvCtxField(c,id,"device",device);
  NvCtxField(c,id,"allocation",allocation);
  if(!device){NvCtxField(c,id,"device_present",0);ok=TRUE;goto done;}
  if(!NvCtxHeap(map,used,step,device,0x7a8U)){failure=EFI_COMPROMISED_DATA;goto done;}
  UINTN vtable=*(volatile const UINTN *)device;
  NvCtxField(c,id,"device_vtable",vtable);
  if((UINTN)image->ImageBase>~(UINTN)0-vtableRva ||
     vtable!=(UINTN)image->ImageBase+vtableRva){failure=EFI_COMPROMISED_DATA;goto done;}
  UINTN adapter=*(volatile const UINTN *)(device+0x70U);
  UINTN embedded=*(volatile const UINTN *)(device+0x78U);
  NvCtxField(c,id,"adapter",adapter);
  NvCtxField(c,id,"embedded",embedded);
  if(adapter) {
    if(!NvCtxHeap(map,used,step,adapter,sizeof(UINTN))){failure=EFI_COMPROMISED_DATA;goto done;}
    NvCtxField(c,id,"adapter_vtable",*(volatile const UINTN *)adapter);
  }
  if(embedded) {
    if(!NvCtxHeap(map,used,step,embedded,sizeof(UINTN))){failure=EFI_COMPROMISED_DATA;goto done;}
    NvCtxField(c,id,"embedded_vtable",*(volatile const UINTN *)embedded);
  }
  ok=TRUE;
done:
  if(map && bs && bs->FreePool) {
    EFI_STATUS freed=bs->FreePool(map);
    if(freed!=EFI_SUCCESS){failure=freed;ok=FALSE;}
  }
  NvCtxField(c,id,"snapshot_complete",ok?1:0);
  if(!ok)Problem(c,"nvgop-context-snapshot",failure);
}
#endif

static VOID NvEvidenceImage(CAPTURE *c,EFI_FILE_PROTOCOL *root,const GU_NV_EVIDENCE *v) {
  UINT32 id=v->Config[0];
  const UINT32 expectedSubsystem=id==0x268410deU?0x88e61043U:0xb61219daU;
  const UINT32 expectedVersion=id==0x268410deU?0x7000bU:0x60010U;
  const UINTN expectedSize=id==0x268410deU?0x278e0U:0x26ae0U;
  const UINTN expectedStop=id==0x268410deU?0x6ecU:0x678U;
  const CHAR16 *expectedName=id==0x268410deU?L"nvgop-ad1xx":L"nvgop-ga1xx";
  EFI_BOOT_SERVICES *bs=c->Table->BootServices;
#ifdef GU_NVGOP_CONTEXT_EVIDENCE
  NvCtxField(c,id,"driver_evidence_begin",1);
#endif
  if(!root || !root->Open || !root->Write || !root->Close ||
     (id!=0x268410deU && id!=0x220a10deU) || v->Config[2]!=0x030000a1U ||
     v->Config[11]!=expectedSubsystem || v->Segment!=0 ||
     v->Bus!=(id==0x268410deU?1U:4U) ||
     !ProbeUnchanged(c,v->Handle,v->Io,v->Config,v->Segment,v->Bus)) {
#ifdef GU_NVGOP_CONTEXT_EVIDENCE
    NvCtxField(c,id,"pci_identity_ok",0);
#endif
    Problem(c,"nvgop-evidence-pci-identity",EFI_NOT_READY);return;
  }
  EFI_OPEN_PROTOCOL_INFORMATION_ENTRY *opens=NULL;
  UINTN n=0;EFI_HANDLE agent=NULL;
  EFI_STATUS s=bs->OpenProtocolInformation?
    bs->OpenProtocolInformation(v->Handle,&PciGuidL,&opens,&n):EFI_UNSUPPORTED;
  if(s!=EFI_SUCCESS || n>512 || (n && !opens)){
    if(opens && bs->FreePool)bs->FreePool(opens);
#ifdef GU_NVGOP_CONTEXT_EVIDENCE
    NvCtxField(c,id,"owner_query_status",s);
#endif
    Problem(c,"nvgop-evidence-open-owners",s==EFI_SUCCESS?EFI_COMPROMISED_DATA:s);return;
  }
  UINTN owners=0;
  for(UINTN i=0;i<n;i++) {
    if(opens[i].Attributes==EFI_OPEN_PROTOCOL_BY_DRIVER) {
      owners++;
      if(opens[i].ControllerHandle!=v->Handle || opens[i].OpenCount!=1 || !opens[i].AgentHandle)break;
      agent=opens[i].AgentHandle;
    }
  }
  EFI_STATUS freeStatus=bs->FreePool?bs->FreePool(opens):EFI_UNSUPPORTED;
  if(freeStatus!=EFI_SUCCESS || owners!=1 || !agent){
#ifdef GU_NVGOP_CONTEXT_EVIDENCE
    NvCtxField(c,id,"driver_owner_ok",0);
#endif
    Problem(c,"nvgop-evidence-owner",EFI_NOT_READY);return;
  }
  EFI_DRIVER_BINDING_PROTOCOL *driver=NULL;
  EFI_LOADED_IMAGE_PROTOCOL *image=NULL;
  s=bs->HandleProtocol(agent,&BindGuidL,(VOID **)&driver);
  if(s!=EFI_SUCCESS || !driver || !driver->Stop || driver->DriverBindingHandle!=agent ||
     driver->ImageHandle!=agent || driver->Version!=expectedVersion ||
     bs->HandleProtocol(agent,&ImgGuidL,(VOID **)&image)!=EFI_SUCCESS || !image ||
     image->DeviceHandle!=v->Handle || image->ImageCodeType!=EfiBootServicesCode ||
     image->ImageSize!=expectedSize || !image->ImageBase ||
     !NvEvidenceName(image->FilePath,expectedName)){
#ifdef GU_NVGOP_CONTEXT_EVIDENCE
    NvCtxField(c,id,"driver_fingerprint_ok",0);
#endif
    Problem(c,"nvgop-evidence-driver-fingerprint",EFI_UNSUPPORTED);return;
  }
  UINTN base=(UINTN)image->ImageBase,stop=(UINTN)driver->Stop;
  if(base>~(UINTN)0-image->ImageSize || stop!=base+expectedStop ||
     !ProbeUnchanged(c,v->Handle,v->Io,v->Config,v->Segment,v->Bus)){
#ifdef GU_NVGOP_CONTEXT_EVIDENCE
    NvCtxField(c,id,"driver_drift_ok",0);
#endif
    Problem(c,"nvgop-evidence-driver-drift",EFI_NOT_READY);return;
  }
  Text(c,"nvgop-evidence-v1 bdf-seg=0x");Hex(c,v->Segment,4);
  Text(c," bus=0x");Hex(c,v->Bus,2);Text(c," pci-id=0x");Hex(c,id,8);
  UINT8 digest[32];
  GuSha256(image->ImageBase,image->ImageSize,digest);
  Text(c," image-index=0x");Hex(c,DumpIndex,2);
  Text(c," loaded-image-sha256=");for(UINTN k=0;k<32;k++)Hex(c,digest[k],2);End(c);
#ifdef GU_NVGOP_CONTEXT_EVIDENCE
  NvCtxField(c,id,"driver_identity_ok",1);
#endif
  DumpImage(c,root,agent);
#ifdef GU_NVGOP_CONTEXT_EVIDENCE
  NvCtxField(c,id,"image_dump_ok",c->Io==EFI_SUCCESS && c->Complete?1:0);
  if(c->Io==EFI_SUCCESS && c->Complete)NvCtxSnapshot(c,v,image);
#endif
}
#endif

static VOID ProbeBar(CAPTURE *c,EFI_PCI_IO_PROTOCOL *io,UINT32 bar,EFI_FILE_PROTOCOL *root,
                     EFI_HANDLE handle,const UINT32 *cfg,UINTN expectedSegment,UINTN expectedBus) {
#ifdef GU_PROBE_GENERIC
  /* PCI inventory only: a missing second GPU must never enable MMIO/PROM reads. */
  Text(c,"probe-deep-v2 skipped=passive-only");End(c);
  return;
#endif
  static const UINT32 offs[]={
    0x000000,0x108154,0x108170,0x108180,0x108354,
    0x118128,0x118234,0x110100,0x1183a4,0x1fa828,
    0x8219c0,0x822804,0x823804,0x82381c,0x823820,0x824140
  };
  UINT8 *page=NULL;EFI_STATUS s;
#ifdef GU_CHECKED_PROBE
  GU_PROBE_PIN pin;
  if(!GuProbeTakePin(c,io,&pin)){Problem(c,"probe-capabilities",EFI_NOT_READY);return;}
  if(!ProbeEnvelope(c,io,cfg)){Problem(c,"probe-unreviewed-envelope",EFI_UNSUPPORTED);return;}
  if(!GuProbePinSame(c,&pin)){Problem(c,"probe-capabilities-changed",EFI_NOT_READY);return;}
  s=pin.Allocate(EfiBootServicesData,0x100000,(VOID **)&page);
  if(s!=EFI_SUCCESS || !page){if(page)pin.Free(page);Problem(c,"prom-alloc",s==EFI_SUCCESS?EFI_OUT_OF_RESOURCES:s);return;}
  if(!GuProbePinSame(c,&pin)){pin.Free(page);Problem(c,"probe-capabilities-changed",EFI_NOT_READY);return;}
  /* The release's CapturePermit requires the PciIo attribute cache to match the raw IO/MEM/BME
   * command bits. Record it here, read-only (Get only), so a local profile can be refused before
   * any release instead of stopping mid-release. A protocol call, so it precedes the recheck. */
  UINT64 pciAttributes=0;
  EFI_STATUS attributesStatus=io->Attributes?io->Attributes(io,EfiPciIoAttributeOperationGet,0,&pciAttributes):EFI_UNSUPPORTED;
  if(!GuProbePinSame(c,&pin) || !ProbeUnchanged(c,handle,io,cfg,expectedSegment,expectedBus) || !GuProbePinSame(c,&pin)) {
    pin.Free(page);Problem(c,"probe-identity-changed",EFI_NOT_READY);return;
  }
#else
  (void)handle;(void)cfg;(void)expectedSegment;(void)expectedBus;
#endif
#ifdef GU_CHECKED_PROBE
  UINT32 values[sizeof(offs)/sizeof(offs[0])];
  EFI_STATUS statuses[sizeof(offs)/sizeof(offs[0])];
  /* No logging, file I/O, allocation or other firmware-service call between
   * the final raw-state check and this bounded MMIO batch. Log afterwards. */
  for(UINTN i=0;i<sizeof(offs)/sizeof(offs[0]);i++) {
    values[i]=0xdeadbeef;
    statuses[i]=io->Mem.Read(io,EfiPciIoWidthUint32,0,offs[i],1,&values[i]);
  }
  s=EFI_SUCCESS;
  for(UINTN i=0;i<0x100000/4 && s==EFI_SUCCESS;i++)
    s=io->Mem.Read(io,EfiPciIoWidthUint32,0,0x300000+i*4,1,((UINT32*)page)+i);
  EFI_STATUS promStatus=s;
#endif
  Text(c,"probe-bar0 base=0x");Hex(c,bar,16);End(c);
#ifdef GU_CHECKED_PROBE
  Text(c,"pci-attributes status=0x");Hex(c,attributesStatus,16);Text(c," value=0x");Hex(c,pciAttributes,16);End(c);
#endif
  for(UINTN i=0;i<sizeof(offs)/sizeof(offs[0]);i++) {
    UINT32 v=0xdeadbeef;
#ifdef GU_CHECKED_PROBE
    EFI_STATUS s=statuses[i];v=values[i];
#else
    EFI_STATUS s=io->Mem.Read(io,EfiPciIoWidthUint32,0,offs[i],1,&v);
#endif
    Text(c,"mmio off=0x");Hex(c,offs[i],8);Text(c," status=0x");Hex(c,s,16);Text(c," value=0x");Hex(c,v,8);End(c);
  }
  UINT8 digest[32];
#ifndef GU_CHECKED_PROBE
  s=c->Table->BootServices->AllocatePool(EfiBootServicesData,0x100000,(VOID **)&page);
#else
  s=EFI_SUCCESS;
#endif
  if(s==EFI_SUCCESS && page) {
#ifndef GU_CHECKED_PROBE
    for(UINTN i=0;i<0x100000/4 && s==EFI_SUCCESS;i++)
      s=io->Mem.Read(io,EfiPciIoWidthUint32,0,0x300000+i*4,1,((UINT32*)page)+i);
#else
    s=promStatus;
#endif
    if(s==EFI_SUCCESS) {
      GuSha256(page,0x100000,digest);
      Text(c,"prom sha256=");for(UINTN i=0;i<32;i++)Hex(c,digest[i],2);End(c);
#if defined(GU_PROBE_GENERIC) || defined(GU_PROBE_DUMP_PROM)
      if(root)DumpProm(c,root,page);else Problem(c,"prom-dump-volume",EFI_NOT_FOUND);
#else
      (void)root; /* Reviewed fixed-profile diagnostics remain hash-only. */
#endif
    } else { Problem(c,"prom-read",s); }
#ifdef GU_CHECKED_PROBE
    if(pin.Free(page)!=EFI_SUCCESS)Problem(c,"prom-free",EFI_DEVICE_ERROR);
#else
    if(c->Table->BootServices->FreePool(page)!=EFI_SUCCESS)Problem(c,"prom-free",EFI_DEVICE_ERROR);
#endif
  } else Problem(c,"prom-alloc",s==EFI_SUCCESS?EFI_OUT_OF_RESOURCES:s);
}

static VOID ProbeDrivers(CAPTURE *c,EFI_FILE_PROTOCOL *root) {
#ifdef GU_PROBE_GENERIC
  Text(c,"probe-driver-dumps-v2 skipped=passive-only");End(c);
  return;
#endif
  EFI_HANDLE *hs=NULL;UINTN n=0;
  if(SysT->BootServices->LocateHandleBuffer(ByProtocol,&BindGuidL,NULL,&n,&hs)!=EFI_SUCCESS||!hs)return;
  Text(c,"driver-bindings=");Hex(c,n,8);End(c);
  for(UINTN i=0;i<n && c->Io==EFI_SUCCESS;i++) {
    EFI_DRIVER_BINDING_PROTOCOL *d=NULL;
    if(SysT->BootServices->HandleProtocol(hs[i],&BindGuidL,(VOID **)&d)!=EFI_SUCCESS||!d)continue;
    Text(c,"binding handle=0x");Hex(c,(UINTN)hs[i],12);Text(c," image=0x");Hex(c,(UINTN)d->ImageHandle,12);
    Text(c," version=0x");Hex(c,d->Version,8);Text(c," stop=0x");Hex(c,(UINTN)d->Stop,12);End(c);
    if(d->ImageHandle)DumpImage(c,root,d->ImageHandle);
  }
  SysT->BootServices->FreePool(hs);
}

#ifdef GU_PROBE_GENERIC
/* Passive metadata only. This does not enable MMIO, PROM, GPU reset, or unlock
 * eligibility for multiple controllers. Never infer zero from failed reads. */
static UINT64 InventoryBdf[1024];
static UINTN InventorySeen;
static UINTN InventoryDisplays;
static UINTN InventoryFailures;
static VOID InventoryDisplay(CAPTURE *c,EFI_HANDLE handle,EFI_PCI_IO_PROTOCOL *io,
                             UINT32 id,UINT32 cls) {
  EFI_BOOT_SERVICES *bs=SysT->BootServices;
  UINTN seg=~(UINTN)0,bus=~(UINTN)0,dev=~(UINTN)0,fun=~(UINTN)0;
  UINT32 first[64],second[64];
  UINT64 attrs=~(UINT64)0,supported=~(UINT64)0;
  EFI_STATUS loc=EFI_UNSUPPORTED,readA=EFI_UNSUPPORTED,readB=EFI_UNSUPPORTED;
  EFI_STATUS get=EFI_UNSUPPORTED,sup=EFI_UNSUPPORTED,pathStatus=EFI_UNSUPPORTED;
  EFI_DEVICE_PATH_PROTOCOL *path=NULL;
  BOOLEAN stable=FALSE,duplicate=FALSE;
  InventoryDisplays++;
  if(io->GetLocation)loc=io->GetLocation(io,&seg,&bus,&dev,&fun);
  if(io->Pci.Read) {
    for(UINTN k=0;k<64;k++){first[k]=0xa5a5a5a5U;second[k]=0x5a5a5a5aU;}
    readA=io->Pci.Read(io,EfiPciIoWidthUint32,0,64,first);
    if(readA==EFI_SUCCESS)readB=io->Pci.Read(io,EfiPciIoWidthUint32,0,64,second);
  }
  if(io->Attributes){
    get=io->Attributes(io,EfiPciIoAttributeOperationGet,0,&attrs);
    sup=io->Attributes(io,EfiPciIoAttributeOperationSupported,0,&supported);
  }
  if(bs->HandleProtocol)pathStatus=bs->HandleProtocol(handle,&PathGuidL,(VOID **)&path);
  if(loc==EFI_SUCCESS && seg<=0xffffU && bus<=255 && dev<=31 && fun<=7) {
    UINT64 key=((UINT64)seg<<24)|((UINT64)bus<<16)|((UINT64)dev<<8)|(UINT64)fun;
    for(UINTN j=0;j<InventorySeen;j++)if(InventoryBdf[j]==key)duplicate=TRUE;
    if(InventorySeen<1024)InventoryBdf[InventorySeen++]=key;
    else duplicate=TRUE;
  }
  if(loc==EFI_SUCCESS && readA==EFI_SUCCESS && readB==EFI_SUCCESS &&
     first[0]==id && first[2]==cls) {
    stable=TRUE;
    for(UINTN k=0;k<64;k++)if(first[k]!=second[k]){stable=FALSE;break;}
  }
  Text(c,"probe-display-v2 seg=0x");Hex(c,seg,4);
  Text(c," bus=0x");Hex(c,bus,2);Text(c," dev=0x");Hex(c,dev,2);
  Text(c," fun=0x");Hex(c,fun,2);Text(c," id=0x");Hex(c,id,8);
  Text(c," class=0x");Hex(c,cls,8);
  Text(c," subsystem=0x");Hex(c,readA==EFI_SUCCESS?first[11]:0,8);
  Text(c," command=0x");Hex(c,readA==EFI_SUCCESS?first[1]&0xffffU:0,4);
  Text(c," loc-status=0x");Hex(c,loc,16);
  Text(c," config-status=0x");Hex(c,readA,16);
  Text(c," repeat-status=0x");Hex(c,readB,16);
  Text(c," attrs-status=0x");Hex(c,get,16);
  Text(c," attrs=0x");Hex(c,attrs,16);
  Text(c," supported-status=0x");Hex(c,sup,16);
  Text(c," supported=0x");Hex(c,supported,16);
  Text(c," path-status=0x");Hex(c,pathStatus,16);
  Text(c," stable=");Hex(c,stable?1:0,1);
  Text(c," duplicate=");Hex(c,duplicate?1:0,1);End(c);
  if(pathStatus==EFI_SUCCESS && path)DumpPath(c,path,4096);
  if(!stable || duplicate || loc!=EFI_SUCCESS || seg>0xffffU || bus>255 || dev>31 || fun>7 ||
     get!=EFI_SUCCESS || sup!=EFI_SUCCESS || pathStatus!=EFI_SUCCESS || !path) {
    InventoryFailures++;
    Problem(c,"probe-display-incomplete-or-drift",EFI_NOT_READY);
  }
}
#endif

static VOID ProbeGops(CAPTURE *c) {
  EFI_HANDLE *hs=NULL;UINTN n=0;
  EFI_STATUS s=SysT->BootServices->LocateHandleBuffer(ByProtocol,&GopGuidL,NULL,&n,&hs);
  if(s==EFI_NOT_FOUND){Text(c,"gops=0");End(c);return;}
  if(s!=EFI_SUCCESS||!hs){Problem(c,"gop-enum",s);return;}
  Text(c,"gops=");Hex(c,n,4);End(c);
  for(UINTN i=0;i<n;i++) {
    EFI_DEVICE_PATH_PROTOCOL *dp=NULL;
    EFI_STATUS ps=SysT->BootServices->HandleProtocol(hs[i],&PathGuidL,(VOID **)&dp);
    Text(c,"gop handle=0x");Hex(c,(UINTN)hs[i],12);
    Text(c," path-status=0x");Hex(c,ps,16);Text(c," has-path=");Hex(c,dp?1:0,1);End(c);
    DumpPath(c,dp,4096);
  }
  SysT->BootServices->FreePool(hs);
  Text(c,"console-out=0x");Hex(c,(UINTN)SysT->ConsoleOutHandle,12);
  Text(c," stderr=0x");Hex(c,(UINTN)SysT->StandardErrorHandle,12);
  Text(c," conin=0x");Hex(c,(UINTN)SysT->ConsoleInHandle,12);End(c);
}

EFI_STATUS GuProbeGpu(EFI_SYSTEM_TABLE *t,CAPTURE *c) {
  SysT=t;
  DumpIndex=0;
#ifdef GU_PROBE_GENERIC
  InventorySeen=InventoryDisplays=InventoryFailures=0;
#ifdef GU_NVGOP_DRIVER_EVIDENCE
  GU_NV_EVIDENCE evidence[2];UINTN evidenceCount=0;
#endif
  Text(c,"probe-inventory-v2 begin");End(c);
#ifdef GU_NVGOP_CONTEXT_EVIDENCE
  NvCtxField(c,0x268410deU,"inventory_started",1);
#endif
#endif
#ifdef GU_PROBE_PARENT_BASELINE
  /* A distinct diagnostic invocation owns a fresh observation, never a retry of
   * a correction transaction. Static storage keeps it off the firmware stack. */
  static GU_DS_CAPTURE parentObservation;parentObservation=(GU_DS_CAPTURE){0};
#endif
  EFI_FILE_PROTOCOL *root=c->DumpRoot;
  if(root && !root->Open){Problem(c,"dump-volume",EFI_INVALID_PARAMETER);root=NULL;}
  EFI_BOOT_SERVICES *bs=t->BootServices;EFI_HANDLE *hs=NULL;UINTN n=0,found=0,cfgFailed=0;
  EFI_STATUS cfgError=EFI_SUCCESS;
  EFI_STATUS s=bs->LocateHandleBuffer(ByProtocol,&PciGuidL,NULL,&n,&hs);
  if(s!=EFI_SUCCESS||!hs){Problem(c,"pci-enum",s);return s;}
  if(n>1024){bs->FreePool(hs);Problem(c,"pci-count",EFI_BAD_BUFFER_SIZE);return EFI_BAD_BUFFER_SIZE;}
#ifdef GU_CHECKED_PROBE
  UINTN candidates=0;BOOLEAN inventoryOk=TRUE;
#ifdef GU_PROBE_GENERIC
  EFI_HANDLE targetHandle=NULL;EFI_PCI_IO_PROTOCOL *targetIo=NULL;
  UINT32 targetId=0,targetClass=0;UINTN targetSegment=0,targetBus=0;
  BOOLEAN targetValidated=FALSE;
#endif
  /* Count all display targets before any MMIO/PROM access. Multiple devices
   * cannot share a single PROM.BIN or be used to generate one local profile. */
  for(UINTN i=0;i<n;i++) {
    EFI_PCI_IO_PROTOCOL *io=NULL;UINT32 id=0,cls=0;
    if(bs->HandleProtocol(hs[i],&PciGuidL,(VOID **)&io)!=EFI_SUCCESS || !io || !io->Pci.Read ||
       io->Pci.Read(io,EfiPciIoWidthUint32,0,1,&id)!=EFI_SUCCESS){inventoryOk=FALSE;continue;}
    if((id&0xffffU)!=0x10deU)continue;
    if(io->Pci.Read(io,EfiPciIoWidthUint32,8,1,&cls)!=EFI_SUCCESS){inventoryOk=FALSE;continue;}
    if((cls>>24)!=3)continue;
    candidates++;
#ifdef GU_PROBE_GENERIC
    UINTN seg=0,bus=0,dev=0,fun=0;
    if(!io->GetLocation || io->GetLocation(io,&seg,&bus,&dev,&fun)!=EFI_SUCCESS ||
       seg>0xffffU || !bus || bus>255 || dev || fun){inventoryOk=FALSE;continue;}
#ifndef GU_PROBE_AUTO_BUS
    if(bus!=GU_PROBE_BUS){inventoryOk=FALSE;continue;}
#endif
    targetHandle=hs[i];targetIo=io;targetId=id;targetClass=cls;targetSegment=seg;targetBus=bus;
#endif
  }
#ifdef GU_PROBE_GENERIC
  /* Multiple NVIDIA devices are a supported *observation* case, never a
   * supported deep-read or LOCAL-profile case. */
  if(!inventoryOk)Problem(c,"probe-inventory",EFI_NOT_READY);
  Text(c,"probe-deep-v2 single-nvidia=");Hex(c,inventoryOk && candidates==1?1:0,1);
  Text(c," nvidia-display-count=0x");Hex(c,candidates,4);End(c);
#else
  if(!inventoryOk || candidates!=1)Problem(c,"probe-inventory",EFI_UNSUPPORTED);
#endif
#endif
  Text(c,"probe-pci-handles=");Hex(c,n,8);End(c);
  for(UINTN i=0;i<n && c->Io==EFI_SUCCESS;i++) {
    EFI_PCI_IO_PROTOCOL *io=NULL;UINT32 id=0;
    if(bs->HandleProtocol(hs[i],&PciGuidL,(VOID **)&io)!=EFI_SUCCESS||!io)continue;
    if(!io->Pci.Read || !io->GetLocation){Problem(c,"pci-methods",EFI_UNSUPPORTED);continue;}
    if(io->Pci.Read(io,EfiPciIoWidthUint32,0,1,&id)!=EFI_SUCCESS)continue;
#ifdef GU_PROBE_GENERIC
    UINT32 displayClass=0;
    EFI_STATUS displayStatus=io->Pci.Read(io,EfiPciIoWidthUint32,8,1,&displayClass);
    if(displayStatus!=EFI_SUCCESS){Problem(c,"probe-display-class",displayStatus);continue;}
    if((displayClass>>24)==3)InventoryDisplay(c,hs[i],io,id,displayClass);
#endif
    if(!ProbeTarget(io,id))continue;
    found++;
    UINTN seg=0,bus=0,dev=0,fun=0;
    EFI_STATUS locationStatus=io->GetLocation(io,&seg,&bus,&dev,&fun);
    if(locationStatus==EFI_SUCCESS) {
      Text(c,"probe-target seg=0x");Hex(c,seg,4);Text(c," bus=0x");Hex(c,bus,4);
      Text(c," dev=0x");Hex(c,dev,4);Text(c," fun=0x");Hex(c,fun,4);End(c);
    }
    UINT32 cfg[64];
    for(UINTN j=0;j<64;j++)cfg[j]=0xa5a5a5a5U;
    s=io->Pci.Read(io,EfiPciIoWidthUint32,0,64,cfg);
    PH(c,"cfg256 status=0x",s);
    if(s!=EFI_SUCCESS) {
      /* The BAR base, subsystem id, capability walk and PROM hash all derive
       * from this read. Firmware may return an error after writing part of the
       * buffer, so cfg holds no trustworthy value: record the failure and skip
       * every dependent capture for this device. */
      Problem(c,"cfg256",s);cfgFailed++;
      if(cfgError==EFI_SUCCESS)cfgError=s;
      continue;
    }
    Text(c,"cfg dwords=");for(UINTN j=0;j<64;j++){Hex(c,cfg[j],8);Text(c," ");}End(c);
    UINT32 sub=0;io->Pci.Read(io,EfiPciIoWidthUint32,0x2c,1,&sub);PH(c,"subsystem=0x",sub);
    ProbeCaps(c,io);
#if defined(GU_PROBE_GENERIC) && defined(GU_NVGOP_DRIVER_EVIDENCE)
    if(evidenceCount<2 && locationStatus==EFI_SUCCESS && seg==0 &&
       ((id==0x268410deU && bus==1) || (id==0x220a10deU && bus==4)) && !dev && !fun) {
      GU_NV_EVIDENCE *e=&evidence[evidenceCount++];
      e->Handle=hs[i];e->Io=io;e->Segment=seg;e->Bus=bus;
      for(UINTN k=0;k<64;k++)e->Config[k]=cfg[k];
    }
#endif
    UINT32 bar=cfg[0x10/4]&~0xfU;
#if defined(GU_PROBE_GENERIC) && defined(GU_PROBE_PARENT_BASELINE)
    /* Capture ancestry individually even when shared PROM.BIN forbids deep
     * capture. One device's unavailable ancestry does not authorize the other. */
    if(inventoryOk && candidates!=1 && locationStatus==EFI_SUCCESS &&
       seg<=0xffffU && bus<=255 && !dev && !fun && cfg[0]==id) {
      Text(c,"probe-parent-v2 seg=0x");Hex(c,seg,4);
      Text(c," bus=0x");Hex(c,bus,2);Text(c," id=0x");Hex(c,id,8);End(c);
      parentObservation=(GU_DS_CAPTURE){0};
      EFI_STATUS parentStatus=GuProbeParentBaseline(c,&parentObservation,hs[i],io,cfg,seg,bus);
      if(parentStatus==EFI_COMPROMISED_DATA){Problem(c,"probe-parent-drift",parentStatus);continue;}
    }
#endif
#ifdef GU_CHECKED_PROBE
    if(!inventoryOk || candidates!=1)continue;
#ifdef GU_PROBE_GENERIC
    /* Do not deep-read an unstable or incomplete display inventory. */
    if(InventoryFailures)continue;
#endif
#endif
    UINTN expectedSegment=0,expectedBus=GU_PROBE_BUS;
#ifdef GU_PROBE_GENERIC
    /* Bind this snapshot to the unique device inventoried before external log,
     * resource and allocation callbacks. No re-selection after a mismatch. */
    if(hs[i]!=targetHandle || io!=targetIo || id!=targetId || cfg[0]!=targetId || cfg[2]!=targetClass ||
       locationStatus!=EFI_SUCCESS || seg!=targetSegment || bus!=targetBus || dev || fun) {
      Problem(c,"probe-inventory-changed",EFI_NOT_READY);continue;
    }
    expectedBus=targetBus;
    expectedSegment=targetSegment;
    targetValidated=TRUE;
#endif
#ifdef GU_CHECKED_PROBE
    GU_PROBE_PIN original;
    if(!GuProbeTakePin(c,io,&original)) {
      Problem(c,"probe-capabilities",EFI_NOT_READY);
      if(hs && bs->FreePool)bs->FreePool(hs);
      return EFI_COMPROMISED_DATA;
    }
#endif
#ifdef GU_PROBE_PARENT_BASELINE
    EFI_FREE_POOL release=bs->FreePool;
    EFI_STATUS parent=GuProbeParentBaseline(c,&parentObservation,hs[i],io,cfg,expectedSegment,expectedBus);
    if(parent==EFI_COMPROMISED_DATA) {
      Problem(c,"parent-baseline-capability-changed",EFI_NOT_READY);
      if(hs && release)release(hs);
      return EFI_COMPROMISED_DATA;
    }
    if(c->Io!=EFI_SUCCESS)break;
#endif
    if(bar)ProbeBar(c,io,bar,root,hs[i],cfg,expectedSegment,expectedBus);else Problem(c,"bar0",EFI_UNSUPPORTED);
#ifdef GU_CHECKED_PROBE
    if(!GuProbePinSame(c,&original)) {
      Problem(c,"probe-capabilities-changed",EFI_NOT_READY);if(hs)original.Free(hs);return EFI_COMPROMISED_DATA;
    }
#endif
  }
#ifdef GU_PROBE_GENERIC
  /* A selected target disappearing or turning non-display during the second
   * pass must not become a successful inventory-only capture. */
  if(inventoryOk && candidates==1 && !InventoryFailures && !targetValidated)Problem(c,"probe-inventory-target-lost",EFI_NOT_READY);
#endif
#if defined(GU_PROBE_GENERIC) && defined(GU_NVGOP_DRIVER_EVIDENCE)
  if(inventoryOk && candidates==2 && InventoryDisplays==3 && !InventoryFailures &&
     found==2 && !cfgFailed && evidenceCount==2 &&
     evidence[0].Config[0]!=evidence[1].Config[0] && root) {
    NvEvidenceImage(c,root,&evidence[0]);
    if(c->Io==EFI_SUCCESS && c->Complete)NvEvidenceImage(c,root,&evidence[1]);
  } else {Problem(c,"nvgop-evidence-incomplete-topology",EFI_NOT_READY);}
#endif
#ifdef GU_PROBE_GENERIC
  Text(c,"probe-inventory-v2 end displays=0x");Hex(c,InventoryDisplays,4);
  Text(c," failures=0x");Hex(c,InventoryFailures,4);
  Text(c," complete=");Hex(c,inventoryOk && !InventoryFailures?1:0,1);End(c);
#endif
  if(hs)bs->FreePool(hs);
  Text(c,"probe targets=");Hex(c,found,4);Text(c," cfg-incomplete=");Hex(c,cfgFailed,4);End(c);
  ProbeGops(c);
#ifdef GU_PROBE_GENERIC
  /* Mixed-display inventory does not dump loaded driver binaries with no
   * per-GPU provenance. The passive graph still records driver metadata. */
  if(candidates==1 && inventoryOk) {
    if(root)ProbeDrivers(c,root);else Problem(c,"dump-volume",EFI_NOT_FOUND);
  } else {Text(c,"probe-driver-dumps-v2 skipped=multi-or-incomplete-inventory");End(c);}
#else
  if(root)ProbeDrivers(c,root);else Problem(c,"dump-volume",EFI_NOT_FOUND);
#endif
  /* Report a target that could not be captured rather than a clean success. */
  return found?cfgError:EFI_NOT_FOUND;
}
