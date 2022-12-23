import { IncomingMessage, ServerResponse } from 'http';
/**
 * Hello world.
 */
export declare const hello: () => void;
/**
 * X-Requested-With header check.
 * If not specified, set status 417 to the response.
 * @param req request
 * @param res response
 * @return false if no X-Requested-With header is specified
 */
export declare const checkXRequestedWith: (req: IncomingMessage, res: ServerResponse) => boolean;
/**
 * Sends an feed response(including message) to the client using the specified status.
 * @param res response
 * @param statusCode status code
 * @param message message
 * @return true
 */
export declare const sendMessage: (res: ServerResponse, statusCode: number, message: string) => boolean;
/**
 * login.
 * Request authentication with WSSE.
 * If the login is successful, sets the authentication information in a cookie.
 * @param req request
 * @param res response
 * @param wsse WSSE
 * @param reCaptchaToken reCAPTCHA token
 * @return true if log in has been successful.
 */
export declare const login: (req: IncomingMessage, res: ServerResponse, wsse: string, reCaptchaToken?: string) => Promise<boolean>;
/**
 * logout.
 * If the logout is successful, delete the authentication information in a cookie.
 * @param req request
 * @param res response
 * @return true if log out has been successful.
 */
export declare const logout: (req: IncomingMessage, res: ServerResponse) => Promise<boolean>;
/**
 * get login uid
 * @param req request
 * @param res response
 * @return uid
 */
export declare const uid: (req: IncomingMessage, res: ServerResponse) => Promise<string>;
/**
 * get login whoami
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @return login user information
 */
export declare const whoami: (req: IncomingMessage, res: ServerResponse) => Promise<any>;
/**
 * whether you are logged in
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @return true if logged in
 */
export declare const isLoggedin: (req: IncomingMessage, res: ServerResponse) => Promise<boolean>;
/**
 * register a log entry
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param message message
 * @param title title
 * @param subtitle subtitle
 * @return true if successful
 */
export declare const log: (req: IncomingMessage, res: ServerResponse, message: string, title?: string, subtitle?: string) => Promise<boolean>;
/**
 * get entry
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param uri key
 * @return entry
 */
export declare const getEntry: (req: IncomingMessage, res: ServerResponse, uri: string) => Promise<any>;
/**
 * get entry
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param uri key and conditions
 * @return feed (entry array)
 */
export declare const getFeed: (req: IncomingMessage, res: ServerResponse, uri: string) => Promise<any>;
/**
 * get count
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param uri key and conditions
 * @return count
 */
export declare const count: (req: IncomingMessage, res: ServerResponse, uri: string) => Promise<number | null>;
/**
 * register entries
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param feed entries (JSON)
 * @param uri parent key if not specified in entry
 * @return registed entries
 */
export declare const post: (req: IncomingMessage, res: ServerResponse, feed: any, uri?: string) => Promise<any>;
/**
 * update entries
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param feed entries (JSON)
 * @param isbulk Forcibly execute even if it exceeds the upper limit of entries of request feed.
 * @param parallel Execute parallel if this param is true. Valid only if 'isbulk' is true.
 * @param async Execute asynchronous if this param is true. Valid only if 'isbulk' is true.
 * @return updated entries
 */
export declare const put: (req: IncomingMessage, res: ServerResponse, feed: any, isbulk?: boolean, parallel?: boolean, async?: boolean) => Promise<any>;
/**
 * delete entry
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param uri key
 * @param revision number of revision
 * @return true if successful
 */
export declare const deleteEntry: (req: IncomingMessage, res: ServerResponse, uri: string, revision?: number) => Promise<boolean>;
/**
 * delete folder
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param uri parent key
 * @param async execute async
 * @return true if successful
 */
export declare const deleteFolder: (req: IncomingMessage, res: ServerResponse, uri: string, async?: boolean) => Promise<boolean>;
/**
 * allocate numbers
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param uri key
 * @param num number to allocate
 * @return allocated numbers. comma separated if multiple.
 */
export declare const allocids: (req: IncomingMessage, res: ServerResponse, uri: string, num: number) => Promise<string>;
/**
 * add a number
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param uri key
 * @param num number to add
 * @return added number
 */
export declare const addids: (req: IncomingMessage, res: ServerResponse, uri: string, num: number) => Promise<number | null>;
/**
 * get a added number
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param uri key
 * @return added number
 */
export declare const getids: (req: IncomingMessage, res: ServerResponse, uri: string) => Promise<number | null>;
/**
 * set a number
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param uri key
 * @param num number to set
 * @return set number
 */
export declare const setids: (req: IncomingMessage, res: ServerResponse, uri: string, num: number) => Promise<number | null>;
/**
 * set a addition range
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param uri key
 * @param range addition range
 * @return addition range
 */
export declare const rangeids: (req: IncomingMessage, res: ServerResponse, uri: string, range: string) => Promise<string>;
/**
 * get a addition range
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param uri key
 * @return addition range
 */
export declare const getRangeids: (req: IncomingMessage, res: ServerResponse, uri: string) => Promise<string>;
/**
 * set feed to session
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param name name
 * @param feed entries (JSON)
 * @return true if successful
 */
export declare const setSessionFeed: (req: IncomingMessage, res: ServerResponse, name: string, feed: any) => Promise<boolean>;
/**
 * set entry to session
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param name name
 * @param entry entry (JSON)
 * @return true if successful
 */
export declare const setSessionEntry: (req: IncomingMessage, res: ServerResponse, name: string, entry: any) => Promise<boolean>;
/**
 * set string to session
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param name name
 * @param str string
 * @return true if successful
 */
export declare const setSessionString: (req: IncomingMessage, res: ServerResponse, name: string, str: string) => Promise<boolean>;
/**
 * set number to session
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param name name
 * @param num number
 * @return true if successful
 */
export declare const setSessionLong: (req: IncomingMessage, res: ServerResponse, name: string, num: number) => Promise<boolean>;
/**
 * add number in session
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param name name
 * @param num number to add
 * @return true if successful
 */
export declare const incrementSession: (req: IncomingMessage, res: ServerResponse, name: string, num: number) => Promise<number | null>;
/**
 * delete feed from session
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param name name
 * @return true if successful
 */
export declare const deleteSessionFeed: (req: IncomingMessage, res: ServerResponse, name: string) => Promise<boolean>;
/**
 * delete entry from session
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param name name
 * @return true if successful
 */
export declare const deleteSessionEntry: (req: IncomingMessage, res: ServerResponse, name: string) => Promise<boolean>;
/**
 * delete string from session
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param name name
 * @return true if successful
 */
export declare const deleteSessionString: (req: IncomingMessage, res: ServerResponse, name: string) => Promise<boolean>;
/**
 * delete number from session
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param name name
 * @return true if successful
 */
export declare const deleteSessionLong: (req: IncomingMessage, res: ServerResponse, name: string) => Promise<boolean>;
/**
 * get feed from session
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param name name
 * @return feed
 */
export declare const getSessionFeed: (req: IncomingMessage, res: ServerResponse, name: string) => Promise<any>;
/**
 * get entry from session
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param name name
 * @return entry
 */
export declare const getSessionEntry: (req: IncomingMessage, res: ServerResponse, name: string) => Promise<any>;
/**
 * get string from session
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param name name
 * @return string
 */
export declare const getSessionString: (req: IncomingMessage, res: ServerResponse, name: string) => Promise<string | null>;
/**
 * get number from session
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param name name
 * @return number
 */
export declare const getSessionLong: (req: IncomingMessage, res: ServerResponse, name: string) => Promise<number | null>;
/**
 * pagination
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param uri key and conditions
 * @param pagerange page range
 * @return feed Maximum number of pages in the specified page range, and total count.
 */
export declare const pagination: (req: IncomingMessage, res: ServerResponse, uri: string, pagerange: string) => Promise<any>;
/**
 * get page
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param uri key and conditions
 * @param num page number
 * @return feed Maximum number of pages in the specified page range, and total count.
 */
export declare const getPage: (req: IncomingMessage, res: ServerResponse, uri: string, num: number) => Promise<any>;
/**
 * post data to bigquery
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param feed entries (JSON)
 * @param async execute async
 * @param tablenames key:entity's prop name, value:BigQuery table name
 * @return true if successful
 */
export declare const postBQ: (req: IncomingMessage, res: ServerResponse, feed: any, async?: boolean, tablenames?: any) => Promise<boolean>;
/**
 * delete data from bigquery
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param keys delete keys
 * @param async execute async
 * @param tablenames key:entity's prop name, value:BigQuery table name
 * @return true if successful
 */
export declare const deleteBQ: (req: IncomingMessage, res: ServerResponse, keys: string[], async?: boolean, tablenames?: any) => Promise<boolean>;
/**
 * query bigquery
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param sql query sql
 * @param values values of query arguments
 * @param parent parent name of result json
 * @return query results in JSON format
 */
export declare const getBQ: (req: IncomingMessage, res: ServerResponse, sql: string, values?: any[], parent?: string) => Promise<any>;
/**
 * Search BigQuery and return results in CSV format.
 * @param req request (for authentication)
 * @param res response
 * @param sql query sql
 * @param values values of query arguments
 * @param filename file name of csv
 * @param parent parent name of result json
 * @return true
 */
export declare const getBQCsv: (req: IncomingMessage, res: ServerResponse, sql: string, values?: any[], filename?: string, parent?: string) => Promise<boolean>;
/**
 * Create PDF
 * @param req request (for authentication)
 * @param res response
 * @param htmlTemplate PDF layout
 * @param filename PDF file name
 * @return true
 */
export declare const toPdf: (req: IncomingMessage, res: ServerResponse, htmlTemplate: string, filename?: string) => Promise<boolean>;
/**
 * put the signature of uri and revision.
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param uri key
 * @param revision revision
 * @return signed entry
 */
export declare const putSignature: (req: IncomingMessage, res: ServerResponse, uri: string, revision?: number) => Promise<any>;
/**
 * puts the signature of uri and revision.
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param feed entries
 * @return signed entries
 */
export declare const putSignatures: (req: IncomingMessage, res: ServerResponse, feed: any) => Promise<any>;
/**
 * delete the signature.
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param uri key
 * @param revision revision
 * @return true if successful
 */
export declare const deleteSignature: (req: IncomingMessage, res: ServerResponse, uri: string, revision?: number) => Promise<boolean>;
/**
 * check the signature.
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param uri key
 * @return true if the signature is valid
 */
export declare const checkSignature: (req: IncomingMessage, res: ServerResponse, uri: string) => Promise<boolean>;
/**
 * Send an mail (with attachments)
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param entry email contents
 * @param to email addresses to
 * @param cc email addresses cc
 * @param bcc email addresses bcc
 * @param attachments keys of attachment files
 * @return true if successful
 */
export declare const sendMail: (req: IncomingMessage, res: ServerResponse, entry: any, to: string[], cc?: string[], bcc?: string[], attachments?: string[]) => Promise<boolean>;
/**
 * push notification to clients.
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param message message
 * @param to clients to
 * @param title title
 * @param subtitle subtitle (Expo)
 * @param imageUrl url of image (FCM)
 * @param data key value data (Expo)
 * @return true if successful
 */
export declare const pushNotification: (req: IncomingMessage, res: ServerResponse, message: string, to: string[], title?: string, subtitle?: string, imageUrl?: string, data?: any) => Promise<boolean>;
/**
 * set status of MessageQueue.
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param flag true if on, false if off
 * @param channel channel
 */
export declare const setMessageQueueStatus: (req: IncomingMessage, res: ServerResponse, flag: boolean, channel: string) => Promise<boolean>;
/**
 * set MessageQueue.
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param feed entries (JSON)
 * @param channel channel
 * @return true if successful
 */
export declare const setMessageQueue: (req: IncomingMessage, res: ServerResponse, feed: any, channel: string) => Promise<boolean>;
/**
 * get feed from session
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param name name
 * @return feed
 */
export declare const getMessageQueue: (req: IncomingMessage, res: ServerResponse, channel: string) => Promise<any>;
/**
 * join to the group
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param group group
 * @param selfid hierarchical name under my group alias
 * @return feed
 */
export declare const joinGroup: (req: IncomingMessage, res: ServerResponse, group: string, selfid: string) => Promise<any>;
/**
 * leave from the group
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param group group
 * @return feed
 */
export declare const leaveGroup: (req: IncomingMessage, res: ServerResponse, group: string) => Promise<boolean>;
/**
 * Error returned from vte.cx
 */
export declare class VtecxNextError extends Error {
    status: number;
    constructor(status: number, message: string);
}
