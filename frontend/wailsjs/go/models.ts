export namespace live {
	
	export class Stats {
	    published: number;
	    dropped: number;
	    emitted: number;
	    queued: number;
	
	    static createFrom(source: any = {}) {
	        return new Stats(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.published = source["published"];
	        this.dropped = source["dropped"];
	        this.emitted = source["emitted"];
	        this.queued = source["queued"];
	    }
	}

}

export namespace main {
	
	export class StorageStats {
	    available: boolean;
	    error?: string;
	    enqueued: number;
	    saved: number;
	    failed: number;
	    unsaved: number;
	    abandoned: number;
	    behind: number;
	    queued: number;
	    lastError: string;
	
	    static createFrom(source: any = {}) {
	        return new StorageStats(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.available = source["available"];
	        this.error = source["error"];
	        this.enqueued = source["enqueued"];
	        this.saved = source["saved"];
	        this.failed = source["failed"];
	        this.unsaved = source["unsaved"];
	        this.abandoned = source["abandoned"];
	        this.behind = source["behind"];
	        this.queued = source["queued"];
	        this.lastError = source["lastError"];
	    }
	}
	export class AppStats {
	    live: live.Stats;
	    devSynth: boolean;
	    streaming: boolean;
	    ratePerSec: number;
	    lastId: number;
	    storage: StorageStats;
	
	    static createFrom(source: any = {}) {
	        return new AppStats(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.live = this.convertValues(source["live"], live.Stats);
	        this.devSynth = source["devSynth"];
	        this.streaming = source["streaming"];
	        this.ratePerSec = source["ratePerSec"];
	        this.lastId = source["lastId"];
	        this.storage = this.convertValues(source["storage"], StorageStats);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class HeaderField {
	    name: string;
	    value: string;
	    malformed: boolean;
	
	    static createFrom(source: any = {}) {
	        return new HeaderField(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.value = source["value"];
	        this.malformed = source["malformed"];
	    }
	}
	export class MessageView {
	    captured: boolean;
	    startLine: string;
	    headers: HeaderField[];
	    head: string;
	    body: string;
	    bodyEncoding: string;
	    bodyBytes: number;
	    bodyShown: number;
	    bodyViewTruncated: boolean;
	    bodyTruncated: boolean;
	
	    static createFrom(source: any = {}) {
	        return new MessageView(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.captured = source["captured"];
	        this.startLine = source["startLine"];
	        this.headers = this.convertValues(source["headers"], HeaderField);
	        this.head = source["head"];
	        this.body = source["body"];
	        this.bodyEncoding = source["bodyEncoding"];
	        this.bodyBytes = source["bodyBytes"];
	        this.bodyShown = source["bodyShown"];
	        this.bodyViewTruncated = source["bodyViewTruncated"];
	        this.bodyTruncated = source["bodyTruncated"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ExchangeView {
	    id: number;
	    request: MessageView;
	    response: MessageView;
	    proxyError: string;
	    synthetic: boolean;
	
	    static createFrom(source: any = {}) {
	        return new ExchangeView(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.request = this.convertValues(source["request"], MessageView);
	        this.response = this.convertValues(source["response"], MessageView);
	        this.proxyError = source["proxyError"];
	        this.synthetic = source["synthetic"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	
	export class ProxyStatus {
	    listening: boolean;
	    addr?: string;
	    error?: string;
	
	    static createFrom(source: any = {}) {
	        return new ProxyStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.listening = source["listening"];
	        this.addr = source["addr"];
	        this.error = source["error"];
	    }
	}

}

export namespace synth {
	
	export class Exchange {
	    id: number;
	    startedAt: number;
	    method: string;
	    scheme: string;
	    host: string;
	    port: number;
	    path: string;
	    status: number;
	    reqSize: number;
	    respSize: number;
	    mime: string;
	    durationMs: number;
	    isLLM: boolean;
	    llmReason: string;
	
	    static createFrom(source: any = {}) {
	        return new Exchange(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.startedAt = source["startedAt"];
	        this.method = source["method"];
	        this.scheme = source["scheme"];
	        this.host = source["host"];
	        this.port = source["port"];
	        this.path = source["path"];
	        this.status = source["status"];
	        this.reqSize = source["reqSize"];
	        this.respSize = source["respSize"];
	        this.mime = source["mime"];
	        this.durationMs = source["durationMs"];
	        this.isLLM = source["isLLM"];
	        this.llmReason = source["llmReason"];
	    }
	}

}

