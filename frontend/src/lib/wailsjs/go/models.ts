export namespace main {
	
	export class AccessTokenResponse {
	    access_token: string;
	    expires_in: number;
	    token_type: string;
	
	    static createFrom(source: any = {}) {
	        return new AccessTokenResponse(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.access_token = source["access_token"];
	        this.expires_in = source["expires_in"];
	        this.token_type = source["token_type"];
	    }
	}
	export class ExecutableDetails {
	    executableName: string;
	    gameId: number;
	    minutesPlayed: number;
	
	    static createFrom(source: any = {}) {
	        return new ExecutableDetails(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.executableName = source["executableName"];
	        this.gameId = source["gameId"];
	        this.minutesPlayed = source["minutesPlayed"];
	    }
	}
	export class SimplifiedIgdbCover {
	    id: number;
	    image_id?: string;
	
	    static createFrom(source: any = {}) {
	        return new SimplifiedIgdbCover(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.image_id = source["image_id"];
	    }
	}
	export class IgdbGame {
	    id: number;
	    name: string;
	    cover: SimplifiedIgdbCover;
	
	    static createFrom(source: any = {}) {
	        return new IgdbGame(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.cover = this.convertValues(source["cover"], SimplifiedIgdbCover);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice) {
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
	export class GetGameByIdResponse {
	    game: IgdbGame;
	    error: string;
	
	    static createFrom(source: any = {}) {
	        return new GetGameByIdResponse(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.game = this.convertValues(source["game"], IgdbGame);
	        this.error = source["error"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice) {
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
	export class GetRandomGamesResponse {
	    games: IgdbGame[];
	    error: string;
	
	    static createFrom(source: any = {}) {
	        return new GetRandomGamesResponse(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.games = this.convertValues(source["games"], IgdbGame);
	        this.error = source["error"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice) {
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
	export class UserSettings {
	    executablePaths: string;
	    processMonitoringEnabled: boolean;
	
	    static createFrom(source: any = {}) {
	        return new UserSettings(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.executablePaths = source["executablePaths"];
	        this.processMonitoringEnabled = source["processMonitoringEnabled"];
	    }
	}
	export class GetUserSettingsResponse {
	    preferences: UserSettings;
	    error: any;
	
	    static createFrom(source: any = {}) {
	        return new GetUserSettingsResponse(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.preferences = this.convertValues(source["preferences"], UserSettings);
	        this.error = source["error"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice) {
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
	
	export class InsertExecutableDetailsResponse {
	    details: ExecutableDetails;
	    error: any;
	
	    static createFrom(source: any = {}) {
	        return new InsertExecutableDetailsResponse(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.details = this.convertValues(source["details"], ExecutableDetails);
	        this.error = source["error"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice) {
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
	export class Log {
	    title: string;
	    // Go type: time
	    date: any;
	    rating: number;
	    notes: string;
	    // Go type: LogStatus
	    status: any;
	    statusId: string;
	    finished: boolean;
	    timePlayedMinutes: number;
	
	    static createFrom(source: any = {}) {
	        return new Log(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.title = source["title"];
	        this.date = this.convertValues(source["date"], null);
	        this.rating = source["rating"];
	        this.notes = source["notes"];
	        this.status = this.convertValues(source["status"], null);
	        this.statusId = source["statusId"];
	        this.finished = source["finished"];
	        this.timePlayedMinutes = source["timePlayedMinutes"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice) {
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
	export class InsertGameLogResponse {
	    log: Log;
	    errors: {[key: string]: string};
	
	    static createFrom(source: any = {}) {
	        return new InsertGameLogResponse(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.log = this.convertValues(source["log"], Log);
	        this.errors = source["errors"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice) {
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
	
	export class TimePlayed {
	    hours: number;
	    minutes: number;
	
	    static createFrom(source: any = {}) {
	        return new TimePlayed(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.hours = source["hours"];
	        this.minutes = source["minutes"];
	    }
	}
	export class LogData {
	    title: string;
	    // Go type: time
	    date: any;
	    rating: number;
	    notes?: string;
	    status: string;
	    finished: boolean;
	    timePlayed: TimePlayed;
	
	    static createFrom(source: any = {}) {
	        return new LogData(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.title = source["title"];
	        this.date = this.convertValues(source["date"], null);
	        this.rating = source["rating"];
	        this.notes = source["notes"];
	        this.status = source["status"];
	        this.finished = source["finished"];
	        this.timePlayed = this.convertValues(source["timePlayed"], TimePlayed);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice) {
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
	export class OpenDirectoryDialogResponse {
	    selectedDirectory: string;
	    error: any;
	
	    static createFrom(source: any = {}) {
	        return new OpenDirectoryDialogResponse(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.selectedDirectory = source["selectedDirectory"];
	        this.error = source["error"];
	    }
	}
	export class SearchForGameResponse {
	    games: IgdbGame[];
	    error: string;
	
	    static createFrom(source: any = {}) {
	        return new SearchForGameResponse(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.games = this.convertValues(source["games"], IgdbGame);
	        this.error = source["error"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice) {
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
	
	
	
	export class UserSettingsData {
	    executablePaths: string;
	    processMonitoringEnabled: boolean;
	
	    static createFrom(source: any = {}) {
	        return new UserSettingsData(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.executablePaths = source["executablePaths"];
	        this.processMonitoringEnabled = source["processMonitoringEnabled"];
	    }
	}

}

