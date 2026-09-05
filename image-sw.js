// 圖片解密 Service Worker
//
// 攔截 <BASE>images/** 的請求，抓取加密後的圖檔（AES-GCM，格式：12B IV + 密文 + 16B tag），
// 用存放於 IndexedDB 的 CryptoKey 解密後回傳。金鑰由主執行緒（useEncryption.ts）
// 透過 idb-keyval 寫入預設 store（db "keyval-store" / store "keyval" / key "cryptoKey"）；
// IndexedDB 在 window 與 Service Worker 兩個環境皆可存取，故 SW 可自行讀取，無需 postMessage。
//
// 僅在 production build 註冊（見 registerSW.ts）；dev 不註冊，圖片走明文靜態檔。

const BASE = new URL(self.registration.scope).pathname // 例："/magic-database/"
const IMAGES_PREFIX = `${BASE}images/`

const MIME = {
	jpg: "image/jpeg",
	jpeg: "image/jpeg",
	png: "image/png",
	webp: "image/webp",
	gif: "image/gif",
	svg: "image/svg+xml",
}

// ── 以最小原生 IndexedDB 讀取 idb-keyval 的預設 store ──────────────
// idb-keyval 6.x 預設：dbName="keyval-store", storeName="keyval"
function readCryptoKey() {
	return new Promise((resolve, reject) => {
		const open = indexedDB.open("keyval-store")
		open.onerror = () => reject(open.error)
		open.onsuccess = () => {
			const db = open.result
			// 若 store 尚不存在（使用者從未解鎖），直接視為無金鑰
			if (!db.objectStoreNames.contains("keyval")) {
				db.close()
				resolve(null)
				return
			}
			const tx = db.transaction("keyval", "readonly")
			const req = tx.objectStore("keyval").get("cryptoKey")
			req.onsuccess = () => { resolve(req.result ?? null); db.close() }
			req.onerror = () => { reject(req.error); db.close() }
		}
	})
}

async function decryptImage(request) {
	// 金鑰讀取或解密任一環節失敗時，回退轉發原始請求，避免 respondWith 直接變成
	// network error（至少讓瀏覽器拿到 response，行為可預期）。
	try {
		const key = await readCryptoKey()
		if (!key) {
			// 尚未解鎖：透明轉發原始請求（會拿到密文，無法顯示，但不阻塞）
			return await fetch(request)
		}

		const res = await fetch(request)
		if (!res.ok) return res

		const combined = new Uint8Array(await res.arrayBuffer())
		const iv = combined.slice(0, 12)
		const data = combined.slice(12)

		const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data)

		const ext = new URL(request.url).pathname.split(".").pop().toLowerCase()
		const type = MIME[ext] || "application/octet-stream"

		return new Response(plain, {
			status: 200,
			headers: { "Content-Type": type, "Cache-Control": "no-store" },
		})
	} catch (err) {
		console.error("[image-sw] 解密失敗，回退原始請求：", request.url, err)
		return fetch(request)
	}
}

self.addEventListener("install", () => self.skipWaiting())
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()))

self.addEventListener("fetch", (event) => {
	const url = new URL(event.request.url)
	if (url.origin === self.location.origin && url.pathname.startsWith(IMAGES_PREFIX)) {
		event.respondWith(decryptImage(event.request))
	}
})
