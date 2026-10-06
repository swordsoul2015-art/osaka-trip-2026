const CACHE='travel-studio-shell-v2';
const SHELL=['./','./index.html','./manifest.json','./icon.svg','./icon-192.png','./icon-512.png','https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2.57.4/dist/umd/supabase.min.js'];
self.addEventListener('install',event=>{
  event.waitUntil((async()=>{const cache=await caches.open(CACHE);await Promise.allSettled(SHELL.map(url=>cache.add(url)));await self.skipWaiting();})());
});
self.addEventListener('activate',event=>{
  event.waitUntil((async()=>{const names=await caches.keys();await Promise.all(names.filter(n=>n.startsWith('travel-studio-shell-')&&n!==CACHE).map(n=>caches.delete(n)));await self.clients.claim();})());
});
self.addEventListener('fetch',event=>{
  const request=event.request;
  if(request.method!=='GET')return;
  const url=new URL(request.url),scope=new URL(self.registration.scope);
  const isApp=url.origin===scope.origin&&url.pathname.startsWith(scope.pathname);
  const isLibrary=url.href==='https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2.57.4/dist/umd/supabase.min.js';
  if(!isApp&&!isLibrary)return;
  if(isApp&&!request.mode.startsWith('navigate')&&!SHELL.some(item=>new URL(item,scope).href===url.href))return;
  event.respondWith((async()=>{
    const cache=await caches.open(CACHE);
    try{const response=await fetch(request);if(response.ok&&response.type!=='opaque')await cache.put(request,response.clone());return response;}
    catch(err){const cached=await cache.match(request,{ignoreSearch:request.mode==='navigate'});if(cached)return cached;
      if(request.mode==='navigate'){const shell=await cache.match('./index.html');if(shell)return shell;}
      throw err;
    }
  })());
});
