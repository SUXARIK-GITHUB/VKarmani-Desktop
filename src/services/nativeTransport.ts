/** Track the actual native promise, independently of the renderer deadline.
 * No command arguments/results (credentials/configs) enter this registry. */
export const NATIVE_MUTATIONS=new Set(['request_connect','request_disconnect','rollback_failed_connect','set_system_proxy','repair_runtime_environment']);
export class NativeMutationTracker {
  private next=0;
  private epoch=0;
  private active=new Map<number,string>();
  constructor(private settled:()=>void=()=>undefined,private changed:()=>void=()=>undefined){}
  pending(){return this.active.size>0;}
  get revision(){return this.epoch;}
  commands(){return [...new Set(this.active.values())];}
  async invoke<T>(command:string,start:()=>Promise<T>):Promise<T>{
    if(!NATIVE_MUTATIONS.has(command))return start();
    const id=++this.next;this.active.set(id,command);this.epoch++;this.changed();
    try{return await start();}finally{this.active.delete(id);this.epoch++;this.changed();this.settled();}
  }
}
export const nativeMutations=new NativeMutationTracker(()=>{
  if(typeof window!=='undefined')window.dispatchEvent(new Event('vkarmani:native-mutation-settled'));
},()=>{
  if(typeof window!=='undefined')window.dispatchEvent(new Event('vkarmani:native-mutation-changed'));
});
