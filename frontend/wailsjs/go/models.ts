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
	
	export class AppStats {
	    live: live.Stats;
	    devSynth: boolean;
	    streaming: boolean;
	    ratePerSec: number;
	    lastId: number;
	
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
	
	export class Detail {
	    id: number;
	    request: string;
	    response: string;
	
	    static createFrom(source: any = {}) {
	        return new Detail(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.request = source["request"];
	        this.response = source["response"];
	    }
	}
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
	    }
	}

}

