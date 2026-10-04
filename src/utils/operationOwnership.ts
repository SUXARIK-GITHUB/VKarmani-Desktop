export class OperationOwnership {
  private sequence=0;
  private active=new Map<string,number>();
  acquire(name:string,conflicts:Record<string,string[]>):number|null {
    for(const other of this.active.keys()) if(other===name||(conflicts[name]??[]).includes(other)||(conflicts[other]??[]).includes(name))return null;
    const id=++this.sequence;this.active.set(name,id);return id;
  }
  release(name:string,id:number):boolean {if(this.active.get(name)!==id)return false;this.active.delete(name);return true;}
  snapshot():Record<string,boolean>{return Object.fromEntries(Array.from(this.active.keys(),name=>[name,true]));}
}
