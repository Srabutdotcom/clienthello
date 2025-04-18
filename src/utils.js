//@ts-self-types="../type/utils.d.ts"

export function parseItems(byte, start, lengthOf, Fn, option = {}) {
   // clientHello can have truncated message when creating binders
   /* if (start + lengthOf > byte.length) {
      throw new RangeError("Specified length exceeds available data.");
   } */
   const { parser = null, store = new Set(), storeset = (store, data) => { store.set(data.key, data.value) } } = option
   if (!(store instanceof Set || store instanceof Map || store instanceof Array)) {
      throw new TypeError("store must be an instance of Set, Map, or Array.");
   }

   let offset = start;
   while (true) {
      const item = Fn.from(byte.subarray(offset)); offset += item.length;
      if (parser) parser(item)
      if (store instanceof Set) store.add(item);
      else if (store instanceof Map) storeset(store, item);
      else store.push(item)
      if (offset >= lengthOf) break;//{ debugger; break; }
      if (offset >= byte.length) break;//{ debugger; break; }
   }
   return store
}