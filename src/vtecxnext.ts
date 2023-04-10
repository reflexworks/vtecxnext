import { IncomingMessage, ServerResponse } from 'http'
import SqlString from 'sqlstring'
import formidable, { File } from 'formidable'
import fs from 'fs'
import type { Readable } from 'node:stream'
import urlmodule, { URLSearchParams } from 'url'

/**
 * Hello world.
 */
export const hello = (): void => {
  console.log('Hello vtecxnext.')
}

const SERVLETPATH_DATA = '/d'
const SERVLETPATH_PROVIDER = '/p'
const SERVLETPATH_OAUTH = '/o'
const HEADER_NEXTPAGE = 'x-vtecx-nextpage'

type StatusMessage = {
  status:number,
  message:string,
}

/**
 * X-Requested-With header check.
 * If not specified, set status 417 to the response.
 * @param req request
 * @param res response
 * @return false if no X-Requested-With header is specified
 */
 export const checkXRequestedWith = (req:IncomingMessage, res:ServerResponse): boolean => {
  if (!req.headers['x-requested-with']) {
    res.writeHead(417)
    res.end()
    return false
  }
  return true
}

/**
 * Sends an feed response(including message) to the client using the specified status.
 * @param res response
 * @param statusCode status code
 * @param message message
 * @return true
 */
 export const sendMessage = (res:ServerResponse, statusCode:number, message:string): boolean => {
  const resJson = {'feed' : {'title' : message}}
  res.writeHead(statusCode)
  res.end(JSON.stringify(resJson))
  return true
}

/**
 * login.
 * Request authentication with WSSE.
 * If the login is successful, sets the authentication information in a cookie.
 * @param req request
 * @param res response
 * @param wsse WSSE
 * @param reCaptchaToken reCAPTCHA token
 * @return status and message
 */
 export const login = async (req:IncomingMessage, res:ServerResponse, wsse:string, reCaptchaToken?:string): Promise<StatusMessage> => {
  //console.log('[vtecxnext login] start.')
  // 入力チェック
  checkNotNull(wsse, 'Authentication information')
  // ログイン
  // reCAPTCHA tokenは任意
  const param = reCaptchaToken ? `&g-recaptcha-token=${reCaptchaToken}` : ''
  const method = 'GET'
  const url = `${SERVLETPATH_DATA}/?_login${param}`
  const headers = {'X-WSSE' : `${wsse}`}
  let response:Response
  try {
    response = await requestVtecx(method, url, req, null, headers)
  } catch (e) {
    throw newFetchError(e, true)
  }
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  const data = await response.json()
  return {status:response.status, message:data.feed.title}
}

/**
 * login with RXID.
 * If the login is successful, sets the authentication information in a cookie.
 * @param req request
 * @param res response
 * @param rxid RXID
 * @return status and message
 */
export const loginWithRxid = async (req:IncomingMessage, res:ServerResponse, rxid:string): Promise<StatusMessage> => {
  //console.log('[vtecxnext loginWithRxid] start.')
  // 入力チェック
  checkNotNull(rxid, 'Authentication information')
  // ログイン
  // reCAPTCHA tokenは任意
  const method = 'GET'
  const url = `${SERVLETPATH_DATA}/?_login&_RXID=${rxid}`
  let response:Response
  try {
    response = await requestVtecx(method, url, req)
  } catch (e) {
    throw newFetchError(e, true)
  }
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  const data = await response.json()
  return {status:response.status, message:data.feed.title}
}

/**
 * login with Time-based One Time Password.
 * If the login is successful, sets the authentication information in a cookie.
 * @param req request
 * @param res response
 * @param totp Time-based One Time Password
 * @param isTrustedDevice true if trusted device
 * @return status and message
 */
 export const loginWithTotp = async (req:IncomingMessage, res:ServerResponse, totp:string, isTrustedDevice:boolean): Promise<StatusMessage> => {
  //console.log('[vtecxnext loginWithTotp] start.')
  // 入力チェック
  checkNotNull(totp, 'Authentication information')
  // ログイン
  const method = 'GET'
  const url = `${SERVLETPATH_DATA}/?_login`
  const headers:any = {'Authorization' : `TOTP ${totp}`}
  if (isTrustedDevice) {
    headers['X-TRUSTED-DEVICE'] = 'true'
  }
  //console.log(`[vtecxnext loginWithTotp] headers = ${JSON.stringify(headers)}`)
  let response:Response
  try {
    response = await requestVtecx(method, url, req, null, headers)
  } catch (e) {
    throw newFetchError(e, true)
  }
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  const data = await response.json()
  return {status:response.status, message:data.feed.title}
}

/**
 * logout.
 * If the logout is successful, delete the authentication information in a cookie.
 * @param req request
 * @param res response
 * @return status and message
 */
 export const logout = async (req:IncomingMessage, res:ServerResponse): Promise<StatusMessage> => {
  //console.log('[vtecxnext logout] start.')
  // vte.cxへリクエスト
  const method = 'GET'
  const url = '/d/?_logout'
  let response:Response
  try {
    response = await requestVtecx(method, url, req)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext logout] response=${response}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  //console.log(`[vtecxnext logout] checkVtecxResponse ok.`)
  // 戻り値
  const data = await getJson(response)
  //console.log(`[vtecxnext logout] response message : ${data.feed.title}`)
  //return true
  return {status:response.status, message:data.feed.title}
}

/**
 * get current datetime
 * @return current datetime
 */
export const now = async (): Promise<string> => {
  //console.log('[vtecxnext now] start.')
  // vte.cxへリクエスト
  const method = 'GET'
  const url = '/d/?_now'
  let response:Response
  try {
    response = await requestVtecx(method, url)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext now] response=${response}`)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  const data = await getJson(response)
  return data.feed.title
}

/**
 * get login uid
 * @param req request
 * @param res response
 * @return uid
 */
 export const uid = async (req:IncomingMessage, res:ServerResponse): Promise<string> => {
  //console.log('[vtecxnext uid] start.')
  // vte.cxへリクエスト
  const method = 'GET'
  const url = '/d/?_uid'
  let response:Response
  try {
    response = await requestVtecx(method, url, req)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext uid] response=${response}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  const data = await getJson(response)
  return data.feed.title
}

/**
 * get login account
 * @param req request
 * @param res response
 * @return account
 */
 export const account = async (req:IncomingMessage, res:ServerResponse): Promise<string> => {
  //console.log('[vtecxnext account] start.')
  // vte.cxへリクエスト
  const method = 'GET'
  const url = '/d/?_account'
  let response:Response
  try {
    response = await requestVtecx(method, url, req)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext account] response=${response}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  const data = await getJson(response)
  return data.feed.title
}

/**
 * get login whoami
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @return login user information
 */
 export const whoami = async (req:IncomingMessage, res:ServerResponse): Promise<any> => {
  //console.log('[vtecxnext whoami] start.')
  // vte.cxへリクエスト
  const method = 'GET'
  const url = '/d/?_whoami'
  let response:Response
  try {
    response = await requestVtecx(method, url, req)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext whoami] response=${response}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  return await getJson(response)
}

/**
 * whether you are logged in
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @return true if logged in
 */
 export const isLoggedin = async (req:IncomingMessage, res:ServerResponse): Promise<boolean> => {
  //console.log('[vtecxnext isLoggedin] start.')
  try {
    await uid(req, res)
    return true
  } catch (error) {
    return false
  }
}

/**
 * get login service
 * @param req request
 * @param res response
 * @return service
 */
 export const service = async (req:IncomingMessage, res:ServerResponse): Promise<string> => {
  //console.log('[vtecxnext service] start.')
  // vte.cxへリクエスト
  const method = 'GET'
  const url = '/d/?_service'
  let response:Response
  try {
    response = await requestVtecx(method, url, req)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext service] response=${response}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  const data = await getJson(response)
  return data.feed.title
}

/**
 * get RXID
 * @param req request
 * @param res response
 * @return RXID
 */
 export const rxid = async (req:IncomingMessage, res:ServerResponse): Promise<string> => {
  //console.log('[vtecxnext service] start.')
  // vte.cxへリクエスト
  const method = 'GET'
  const url = '/d/?_getrxid'
  let response:Response
  try {
    response = await requestVtecx(method, url, req)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext uid] response=${response}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  const data = await getJson(response)
  return data.feed.title
}

/**
 * register a log entry
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param message message
 * @param title title
 * @param subtitle subtitle
 * @return true if successful
 */
  export const log = async (req:IncomingMessage, res:ServerResponse, message:string, title?:string, subtitle?:string): Promise<boolean> => {
  const logTitle = title ?? 'JavaScript'
  const logSubtitle = subtitle ?? 'INFO'
  const feed = [{'title' : logTitle, 'subtitle' : logSubtitle, 'summary' : message}]

  const method = 'POST'
  const url = `${SERVLETPATH_PROVIDER}/?_log`
  let response:Response
  try {
    response = await requestVtecx(method, url, req, JSON.stringify(feed))
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext log] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 正常処理
  return true
}

/**
 * get entry
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param uri key
 * @param targetService target service name (for service linkage)
 * @return entry
 */
 export const getEntry = async (req:IncomingMessage, res:ServerResponse, uri:string, targetService?:string): Promise<any> => {
  //console.log('[vtecxnext getEntry] start.')
  // キー入力値チェック
  checkUri(uri)
  // vte.cxへリクエスト
  const method = 'GET'
  const url = `${SERVLETPATH_PROVIDER}${uri}?e`
  let response:Response
  try {
    response = await requestVtecx(method, url, req, null, null, targetService)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext getEntry] response=${response}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  return await getJson(response)
}

/**
 * get feed
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param uri key and conditions
 * @return feed (entry array)
 */
 export const getFeed = async (req:IncomingMessage, res:ServerResponse, uri:string, targetService?:string): Promise<any> => {
  //console.log('[vtecxnext getFeed] start.')
  const vtecxRes:VtecxResponse = await getFeedResponse(req, res, uri, targetService)
  return vtecxRes.data
}

/**
 * get feed
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param uri key and conditions
 * @return feed (entry array). Returns a cursor in the header if more data is available. (x-vtecx-nextpage)
 */
export const getFeedResponse = async (req:IncomingMessage, res:ServerResponse, uri:string, targetService?:string): Promise<VtecxResponse> => {
  //console.log('[vtecxnext getFeedResponse] start.')
  // キー入力値チェック
  checkUri(uri)
  // vte.cxへリクエスト
  const method = 'GET'
  const url = `${SERVLETPATH_PROVIDER}${uri}${uri.includes('?') ? '&' : '?'}f`
  let response:Response
  try {
    response = await requestVtecx(method, url, req, null, null, targetService)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext getFeed] response=${response}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  const data:any = await getJson(response)
  const header:any = {}
  const nextpage = response.headers.get(HEADER_NEXTPAGE)
  if (nextpage) {
    header[HEADER_NEXTPAGE] = nextpage
  }
  return new VtecxResponse(response.status, header, data)
}

/**
 * get count
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param uri key and conditions
 * @return count
 */
 export const count = async (req:IncomingMessage, res:ServerResponse, uri:string, targetService?:string): Promise<number|null> => {
  //console.log('[vtecxnext count] start.')
  const vtecxRes:VtecxResponse = await countResponse(req, res, uri, targetService)
  // 戻り値
  const data = vtecxRes.data
  return vtecxRes.data.feed.title ? Number(data.feed.title) : null
}

/**
 * get count
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param uri key and conditions
 * @return feed. Returns a cursor in the header if more data is available. (x-vtecx-nextpage)
 */
export const countResponse = async (req:IncomingMessage, res:ServerResponse, uri:string, targetService?:string): Promise<VtecxResponse> => {
  //console.log('[vtecxnext countResponse] start.')
  // キー入力値チェック
  checkUri(uri)
  // vte.cxへリクエスト
  const method = 'GET'
  const url = `${SERVLETPATH_PROVIDER}${uri}${uri.includes('?') ? '&' : '?'}c`
  let response:Response
  try {
    response = await requestVtecx(method, url, req, null, null, targetService)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext count] response=${response}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  const data:any = await getJson(response)
  const header:any = {}
  const nextpage = response.headers.get(HEADER_NEXTPAGE)
  if (nextpage) {
    header[HEADER_NEXTPAGE] = nextpage
  }
  return new VtecxResponse(response.status, header, data)
}

/**
 * register entries
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param feed entries (JSON)
 * @param uri parent key if not specified in entry
 * @return registed entries
 */
export const post = async (req:IncomingMessage, res:ServerResponse, feed:any, uri?:string, targetService?:string): Promise<any> => {
  //console.log(`[vtecxnext post] start. feed=${feed}`)
  // 入力チェック
  checkNotNull(feed, 'Feed')
  if (uri) {
    // 値の設定がある場合、キー入力値チェック
    checkUri(uri)
  }
  // vte.cxへリクエスト
  const method = 'POST'
  const url = `${SERVLETPATH_PROVIDER}${uri ? uri : '/'}?e`
  let response:Response
  try {
    response = await requestVtecx(method, url, req, JSON.stringify(feed), null, targetService)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext post] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  return await getJson(response)
}

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
 export const put = async (req:IncomingMessage, res:ServerResponse, feed:any, isbulk?:boolean, parallel?:boolean, async?:boolean, targetService?:string): Promise<any> => {
  //console.log(`[vtecxnext put] start. feed=${feed}`)
  // 入力チェック
  checkNotNull(feed, 'Feed')
  // vte.cxへリクエスト
  const method = 'PUT'
  let additionalParam = ''
  if (isbulk) {
    additionalParam = (parallel ? '&_bulk' : '&_bulkserial') + (async ? '&_async' : '')
  }
  const url = `${SERVLETPATH_PROVIDER}/?e${additionalParam}`
  //console.log(`[vtecxnext put] url=${url}`)
  let response:Response
  try {
    response = await requestVtecx(method, url, req, JSON.stringify(feed), null, targetService)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext put] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  return await getJson(response)
}

/**
 * delete entry
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param uri key
 * @param revision number of revision
 * @return true if successful
 */
 export const deleteEntry = async (req:IncomingMessage, res:ServerResponse, uri:string, revision?:number, targetService?:string): Promise<boolean> => {
  //console.log(`[vtecxnext deleteEntry] start. uri=${uri} revision=${revision}`)
  // キー入力値チェック
  checkUri(uri)
  // vte.cxへリクエスト
  const method = 'DELETE'
  const param = revision ? `&r=${revision}` : ''
  const url = `${SERVLETPATH_PROVIDER}${uri}?e${param}`
  let response:Response
  try {
    response = await requestVtecx(method, url, req, null, null, targetService)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext deleteEntry] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  return true
}

/**
 * delete folder
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param uri parent key
 * @param async execute async
 * @return true if successful
 */
 export const deleteFolder = async (req:IncomingMessage, res:ServerResponse, uri:string, async?:boolean, targetService?:string): Promise<boolean> => {
  //console.log(`[vtecxnext deleteFolder] start. uri=${uri} async=${async}`)
  // キー入力値チェック
  checkUri(uri)
  // vte.cxへリクエスト
  const method = 'DELETE'
  const url = `${SERVLETPATH_PROVIDER}${uri}?_rf${async ? '&_async' : ''}`
  let response:Response
  try {
    response = await requestVtecx(method, url, req, null, null, targetService)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext deleteFolder] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  return true
}

/**
 * allocate numbers
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param uri key
 * @param num number to allocate
 * @return allocated numbers. comma separated if multiple.
 */
 export const allocids = async (req:IncomingMessage, res:ServerResponse, uri:string, num:number, targetService?:string): Promise<string> => {
  //console.log('[vtecxnext allocids] start.')
  // キー入力値チェック
  checkUri(uri)
  checkNotNull(num, 'number to allocate')
  // vte.cxへリクエスト
  const method = 'GET'
  const url = `${SERVLETPATH_PROVIDER}${uri}?_allocids=${num}`
  let response:Response
  try {
    response = await requestVtecx(method, url, req, null, null, targetService)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext allocids] response=${response}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  const data = await getJson(response)
  return data.feed.title
}

/**
 * add a number
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param uri key
 * @param num number to add
 * @return added number
 */
 export const addids = async (req:IncomingMessage, res:ServerResponse, uri:string, num:number, targetService?:string): Promise<number|null> => {
  //console.log('[vtecxnext addids] start.')
  // キー入力値チェック
  checkUri(uri)
  checkNotNull(num, 'number to add')
  // vte.cxへリクエスト
  const method = 'PUT'
  const url = `${SERVLETPATH_PROVIDER}${uri}?_addids=${num}`
  let response:Response
  try {
    response = await requestVtecx(method, url, req, null, null, targetService)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext addids] response=${response}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  const data = await getJson(response)
  return data.feed.title ? Number(data.feed.title) : null
}

/**
 * get a added number
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param uri key
 * @return added number
 */
 export const getids = async (req:IncomingMessage, res:ServerResponse, uri:string, targetService?:string): Promise<number|null> => {
  //console.log('[vtecxnext getids] start.')
  // キー入力値チェック
  checkUri(uri)
  // vte.cxへリクエスト
  const method = 'GET'
  const url = `${SERVLETPATH_PROVIDER}${uri}?_getids`
  let response:Response
  try {
    response = await requestVtecx(method, url, req, null, null, targetService)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext getids] response=${response}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  const data = await getJson(response)
  return data.feed.title ? Number(data.feed.title) : null
}

/**
 * set a number
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param uri key
 * @param num number to set
 * @return set number
 */
 export const setids = async (req:IncomingMessage, res:ServerResponse, uri:string, num:number, targetService?:string): Promise<number|null> => {
  //console.log('[vtecxnext setids] start.')
  // キー入力値チェック
  checkUri(uri)
  checkNotNull(num, 'number to set')
  // vte.cxへリクエスト
  const method = 'PUT'
  const url = `${SERVLETPATH_PROVIDER}${uri}?_setids=${num}`
  let response:Response
  try {
    response = await requestVtecx(method, url, req, null, null, targetService)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext setids] response=${response}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  const data = await getJson(response)
  return data.feed.title ? Number(data.feed.title) : null
}

/**
 * set a addition range
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param uri key
 * @param range addition range
 * @return addition range
 */
 export const rangeids = async (req:IncomingMessage, res:ServerResponse, uri:string, range:string): Promise<string> => {
  //console.log(`[vtecxnext rangeids] start. range=${range}`)
  // 入力値チェック
  checkUri(uri)
  checkNotNull(range, 'range')
  // vte.cxへリクエスト
  const method = 'PUT'
  const url = `${SERVLETPATH_PROVIDER}${uri}?_rangeids`
  const feed = {feed : {'title' : range}}
  let response:Response
  try {
    response = await requestVtecx(method, url, req, JSON.stringify(feed))
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext rangeids] response=${response}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  const data = await getJson(response)
  return data.feed.title
}

/**
 * get a addition range
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param uri key
 * @return addition range
 */
 export const getRangeids = async (req:IncomingMessage, res:ServerResponse, uri:string): Promise<string> => {
  //console.log('[vtecxnext getrangeids] start.')
  // キー入力値チェック
  checkUri(uri)
  // vte.cxへリクエスト
  const method = 'GET'
  const url = `${SERVLETPATH_PROVIDER}${uri}?_rangeids`
  let response:Response
  try {
    response = await requestVtecx(method, url, req)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext getrangeids] response=${response}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  const data = await getJson(response)
  return data.feed.title
}

/**
 * set feed to session
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param name name
 * @param feed entries (JSON)
 * @return true if successful
 */
 export const setSessionFeed = async (req:IncomingMessage, res:ServerResponse, name:string, feed:any): Promise<boolean> => {
  //console.log(`[vtecxnext setSessionFeed] start. name=${name} feed=${feed}`)
  // 入力チェック
  checkNotNull(name, 'Name')
  checkNotNull(feed, 'Feed')
  // vte.cxへリクエスト
  const method = 'PUT'
  const url = `${SERVLETPATH_PROVIDER}/?_sessionfeed=${name}`
  let response:Response
  try {
    response = await requestVtecx(method, url, req, JSON.stringify(feed))
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext setSessionFeed] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  return true
}

/**
 * set entry to session
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param name name
 * @param entry entry (JSON)
 * @return true if successful
 */
 export const setSessionEntry = async (req:IncomingMessage, res:ServerResponse, name:string, entry:any): Promise<boolean> => {
  //console.log(`[vtecxnext setSessionEntry] start. name=${name} entry=${entry}`)
  // 入力チェック
  checkNotNull(name, 'Name')
  checkNotNull(entry, 'Entry')
  // vte.cxへリクエスト
  const method = 'PUT'
  const url = `${SERVLETPATH_PROVIDER}/?_sessionentry=${name}`
  const feed = {feed : {'entry' : entry}}
  let response:Response
  try {
    response = await requestVtecx(method, url, req, JSON.stringify(feed))
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext setSessionEntry] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  return true
}

/**
 * set string to session
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param name name
 * @param str string
 * @return true if successful
 */
 export const setSessionString = async (req:IncomingMessage, res:ServerResponse, name:string, str:string): Promise<boolean> => {
  //console.log(`[vtecxnext setSessionString] start. name=${name} str=${str}`)
  // 入力チェック
  checkNotNull(name, 'Name')
  checkNotNull(str, 'String')
  // vte.cxへリクエスト
  const method = 'PUT'
  const url = `${SERVLETPATH_PROVIDER}/?_sessionstring=${name}`
  const feed = {feed : {'title' : str}}
  let response:Response
  try {
    response = await requestVtecx(method, url, req, JSON.stringify(feed))
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext setSessionString] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  return true
}

/**
 * set number to session
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param name name
 * @param num number
 * @return true if successful
 */
 export const setSessionLong = async (req:IncomingMessage, res:ServerResponse, name:string, num:number): Promise<boolean> => {
  //console.log(`[vtecxnext setSessionLong] start. name=${name} num=${num}`)
  // 入力チェック
  checkNotNull(name, 'Name')
  checkNotNull(num, 'Number')
  // vte.cxへリクエスト
  const method = 'PUT'
  const url = `${SERVLETPATH_PROVIDER}/?_sessionlong=${name}`
  const feed = {feed : {'title' : String(num)}}
  let response:Response
  try {
    response = await requestVtecx(method, url, req, JSON.stringify(feed))
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext setSessionLong] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  return true
}

/**
 * add number in session
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param name name
 * @param num number to add
 * @return true if successful
 */
 export const incrementSession = async (req:IncomingMessage, res:ServerResponse, name:string, num:number): Promise<number|null> => {
  //console.log(`[vtecxnext incrementSession] start. name=${name} num=${num}`)
  // 入力チェック
  checkNotNull(name, 'Name')
  checkNotNull(num, 'Number')
  // vte.cxへリクエスト
  const method = 'PUT'
  const url = `${SERVLETPATH_PROVIDER}/?_sessionincr=${name}&_num=${num}`
  let response:Response
  try {
    response = await requestVtecx(method, url, req)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext incrementSession] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  const data = await getJson(response)
  return data.feed.title ? Number(data.feed.title) : null
}

/**
 * delete feed from session
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param name name
 * @return true if successful
 */
 export const deleteSessionFeed = async (req:IncomingMessage, res:ServerResponse, name:string): Promise<boolean> => {
  //console.log(`[vtecxnext deleteSessionFeed] start. name=${name}`)
  // 入力チェック
  checkNotNull(name, 'Name')
  // vte.cxへリクエスト
  const method = 'DELETE'
  const url = `${SERVLETPATH_PROVIDER}/?_sessionfeed=${name}`
  let response:Response
  try {
    response = await requestVtecx(method, url, req)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext deleteSessionFeed] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  return true
}

/**
 * delete entry from session
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param name name
 * @return true if successful
 */
 export const deleteSessionEntry = async (req:IncomingMessage, res:ServerResponse, name:string): Promise<boolean> => {
  //console.log(`[vtecxnext deleteSessionEntry] start. name=${name}`)
  // 入力チェック
  checkNotNull(name, 'Name')
  // vte.cxへリクエスト
  const method = 'DELETE'
  const url = `${SERVLETPATH_PROVIDER}/?_sessionentry=${name}`
  let response:Response
  try {
    response = await requestVtecx(method, url, req)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext deleteSessionEntry] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  return true
}

/**
 * delete string from session
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param name name
 * @return true if successful
 */
 export const deleteSessionString = async (req:IncomingMessage, res:ServerResponse, name:string): Promise<boolean> => {
  //console.log(`[vtecxnext deleteSessionString] start. name=${name}`)
  // 入力チェック
  checkNotNull(name, 'Name')
  // vte.cxへリクエスト
  const method = 'DELETE'
  const url = `${SERVLETPATH_PROVIDER}/?_sessionstring=${name}`
  let response:Response
  try {
    response = await requestVtecx(method, url, req)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext deleteSessionString] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  return true
}

/**
 * delete number from session
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param name name
 * @return true if successful
 */
 export const deleteSessionLong = async (req:IncomingMessage, res:ServerResponse, name:string): Promise<boolean> => {
  //console.log(`[vtecxnext deleteSessionLong] start. name=${name}`)
  // 入力チェック
  checkNotNull(name, 'Name')
  // vte.cxへリクエスト
  const method = 'DELETE'
  const url = `${SERVLETPATH_PROVIDER}/?_sessionlong=${name}`
  let response:Response
  try {
    response = await requestVtecx(method, url, req)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext deleteSessionLong] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  return true
}

/**
 * get feed from session
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param name name
 * @return feed
 */
 export const getSessionFeed = async (req:IncomingMessage, res:ServerResponse, name:string): Promise<any> => {
  //console.log(`[vtecxnext getSessionFeed] start. name=${name}`)
  // 入力チェック
  checkNotNull(name, 'Name')
  // vte.cxへリクエスト
  const method = 'GET'
  const url = `${SERVLETPATH_PROVIDER}/?_sessionfeed=${name}`
  let response:Response
  try {
    response = await requestVtecx(method, url, req)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext getSessionFeed] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  return await getJson(response)
}

/**
 * get entry from session
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param name name
 * @return entry
 */
 export const getSessionEntry = async (req:IncomingMessage, res:ServerResponse, name:string): Promise<any> => {
  //console.log(`[vtecxnext getSessionEntry] start. name=${name}`)
  // 入力チェック
  checkNotNull(name, 'Name')
  // vte.cxへリクエスト
  const method = 'GET'
  const url = `${SERVLETPATH_PROVIDER}/?_sessionentry=${name}`
  let response:Response
  try {
    response = await requestVtecx(method, url, req)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext getSessionEntry] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  return await getJson(response)
}

/**
 * get string from session
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param name name
 * @return string
 */
 export const getSessionString = async (req:IncomingMessage, res:ServerResponse, name:string): Promise<string|null> => {
  //console.log(`[vtecxnext getSessionString] start. name=${name}`)
  // 入力チェック
  checkNotNull(name, 'Name')
  // vte.cxへリクエスト
  const method = 'GET'
  const url = `${SERVLETPATH_PROVIDER}/?_sessionstring=${name}`
  let response:Response
  try {
    response = await requestVtecx(method, url, req)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext getSessionString] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  const data = await getJson(response)
  if (data) {
    return data.feed.title
  } else {
    return null
  }
}

/**
 * get number from session
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param name name
 * @return number
 */
 export const getSessionLong = async (req:IncomingMessage, res:ServerResponse, name:string): Promise<number|null> => {
  //console.log(`[vtecxnext getSessionLong] start. name=${name}`)
  // 入力チェック
  checkNotNull(name, 'Name')
  // vte.cxへリクエスト
  const method = 'GET'
  const url = `${SERVLETPATH_PROVIDER}/?_sessionlong=${name}`
  let response:Response
  try {
    response = await requestVtecx(method, url, req)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext getSessionLong] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  const data = await getJson(response)
  if (data) {
    return data.feed.title ? Number(data.feed.title) : null
  } else {
    return null
  }
}

/**
 * pagination
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param uri key and conditions
 * @param pagerange page range
 * @return feed Maximum number of pages in the specified page range, and total count.
 */
 export const pagination = async (req:IncomingMessage, res:ServerResponse, uri:string, pagerange:string, targetService?:string): Promise<any> => {
  //console.log('[vtecxnext pagination] start.')
  // キー入力値チェック
  checkUri(uri)
  // vte.cxへリクエスト
  const method = 'GET'
  const url = `${SERVLETPATH_PROVIDER}${uri}${uri.includes('?') ? '&' : '?'}_pagination=${pagerange}`
  let response:Response
  try {
    response = await requestVtecx(method, url, req, null, null, targetService)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext pagination] response=${response}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  return await getJson(response)
}

/**
 * get page
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param uri key and conditions
 * @param num page number
 * @return feed Maximum number of pages in the specified page range, and total count.
 */
 export const getPage = async (req:IncomingMessage, res:ServerResponse, uri:string, num:number, targetService?:string): Promise<any> => {
  //console.log('[vtecxnext getPage] start.')
  // 入力値チェック
  checkUri(uri)
  checkNotNull(num, 'page number')
  // vte.cxへリクエスト
  const method = 'GET'
  const url = `${SERVLETPATH_PROVIDER}${uri}${uri.includes('?') ? '&' : '?'}n=${num}`
  let response:Response
  try {
    response = await requestVtecx(method, url, req, null, null, targetService)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext getPage] response=${response}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  return await getJson(response)
}

/**
 * post data to bigquery
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param feed entries (JSON)
 * @param async execute async
 * @param tablenames key:entity's prop name, value:BigQuery table name
 * @return true if successful
 */
 export const postBQ = async (req:IncomingMessage, res:ServerResponse, feed:any, async?:boolean, tablenames?:any): Promise<boolean> => {
  //console.log(`[vtecxnext postBQ] start. async=${async} feed=${feed}`)
  // 入力チェック
  checkNotNull(feed, 'Feed')
  // リクエストデータ
  const reqFeed = 'feed' in feed ? feed : {'feed' : {'entry' : feed}}
  // テーブル名の指定がある場合は指定
  const tablenamesStr = editBqTableNames(tablenames)
  if (tablenamesStr) {
    reqFeed.feed['title'] = tablenamesStr
  }
  // vte.cxへリクエスト
  const method = 'POST'
  const url = `${SERVLETPATH_PROVIDER}/?_bq${async ? '&_async' : ''}`
  let response:Response
  try {
    response = await requestVtecx(method, url, req, JSON.stringify(reqFeed))
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext postBQ] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  return true
}

/**
 * delete data from bigquery
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param keys delete keys
 * @param async execute async
 * @param tablenames key:entity's prop name, value:BigQuery table name
 * @return true if successful
 */
 export const deleteBQ = async (req:IncomingMessage, res:ServerResponse, keys:string[], async?:boolean, tablenames?:any): Promise<boolean> => {
  //console.log(`[vtecxnext deleteBQ] start. async=${async} keys=${keys}`)
  // 入力チェック
  checkNotNull(keys, 'Key')
  // テーブル名の指定がある場合は指定
  const tablenamesStr = editBqTableNames(tablenames)
  // キーを feed.link.___href にセットする
  const links = []
  let idx = 0
  for (const key of keys) {
    //console.log(`[vtecxnext deleteBQ] key=${key}`)
    links[idx] = {'___href' : key}
    idx++
  }
  const feed:any = {'feed': {}}
  if (tablenamesStr) {
    feed.feed['title'] = tablenamesStr
  }
  feed.feed['link'] = links
  //console.log(`[vtecxnext deleteBQ] feed=${feed}`)
  // vte.cxへリクエスト
  const method = 'DELETE'
  const url = `${SERVLETPATH_PROVIDER}/?_bq${async ? '&_async' : ''}`
  let response:Response
  try {
    response = await requestVtecx(method, url, req, JSON.stringify(feed))
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext deleteBQ] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  return true
}

/**
 * query bigquery
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param sql query sql
 * @param values values of query arguments
 * @param parent parent name of result json
 * @return query results in JSON format
 */
 export const getBQ = async (req:IncomingMessage, res:ServerResponse, sql:string, values?:any[], parent?:string): Promise<any> => {
  //console.log(`[vtecxnext getBQ] start. sql=${sql} values=${values}`)
  // 入力チェック
  checkNotNull(sql, 'Query SQL')
  // 引数生成
  const feed = editGetBqArgument(sql, values, parent)
  // vte.cxへリクエスト
  const method = 'PUT'
  const url = `${SERVLETPATH_PROVIDER}/?_querybq`
  let response:Response
  try {
    response = await requestVtecx(method, url, req, JSON.stringify(feed))
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext getBQ] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  //console.log(`[vtecxnext getBQ] setCookie end.`)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  //console.log(`[vtecxnext getBQ] checkVtecxResponse end.`)
  // 戻り値
  return await response.json()
}

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
 export const getBQCsv = async (req:IncomingMessage, res:ServerResponse, sql:string, values?:any[], filename?:string, parent?:string): Promise<boolean> => {
  //console.log(`[vtecxnext getBQCsv] start. sql=${sql} values=${values}`)
  // 入力チェック
  checkNotNull(sql, 'Query SQL')
  // 引数生成
  const feed = editGetBqArgument(sql, values, parent)
  // vte.cxへリクエスト
  const method = 'PUT'
  const url = `${SERVLETPATH_PROVIDER}/?_querybq&_csv${filename ? '=' + filename : ''}`
  let response:Response
  try {
    response = await requestVtecx(method, url, req, JSON.stringify(feed))
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext getBQCsv] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  //console.log(`[vtecxnext getBQCsv] setCookie end.`)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  //console.log(`[vtecxnext getBQCsv] checkVtecxResponse end.`)
  // 戻り値
  const resData = await response.blob()
  setResponseHeaders(response, res)
  const csvData = await resData.arrayBuffer()
  res.end(csvData)
  return true
}

/**
 * Create PDF.
 * Writes a PDF to the response.
 * @param req request (for authentication)
 * @param res response
 * @param htmlTemplate PDF layout
 * @param filename PDF file name
 * @return true
 */
 export const toPdf = async (req:IncomingMessage, res:ServerResponse, htmlTemplate:string, filename?:string): Promise<boolean> => {
  //console.log(`[vtecxnext toPdf] start. htmlTemplate=${htmlTemplate} filename=${filename}`)
  // 入力チェック
  checkNotNull(htmlTemplate, 'PDF template')
  // vte.cxへリクエスト
  const method = 'PUT'
  const url = `${SERVLETPATH_PROVIDER}/?_pdf${filename ? '=' + filename : ''}`
  let response:Response
  try {
    response = await requestVtecx(method, url, req, htmlTemplate)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext toPdf] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  //console.log(`[vtecxnext toPdf] setCookie end.`)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  //console.log(`[vtecxnext toPdf] checkVtecxResponse end.`)
  // 戻り値
  const resData = await response.blob()
  setResponseHeaders(response, res)
  const csvData:ArrayBuffer = await resData.arrayBuffer()
  res.end(new Uint8Array(csvData))
  return true
}

/**
 * put the signature of uri and revision.
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param uri key
 * @param revision revision
 * @return signed entry
 */
 export const putSignature = async (req:IncomingMessage, res:ServerResponse, uri:string, revision?:number): Promise<any> => {
  //console.log('[vtecxnext putSignature] start.')
  // キー入力値チェック
  checkUri(uri)
  // vte.cxへリクエスト
  const method = 'PUT'
  const url = `${SERVLETPATH_PROVIDER}${uri}?_signature${revision ? '&r=' + revision : ''}`
  let response:Response
  try {
    response = await requestVtecx(method, url, req)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext putSignature] response=${response}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  return await getJson(response)
}

/**
 * puts the signature of uri and revision.
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param feed entries
 * @return signed entries
 */
 export const putSignatures = async (req:IncomingMessage, res:ServerResponse, feed:any): Promise<any> => {
  //console.log('[vtecxnext putSignatures] start.')
  // 入力チェック
  checkNotNull(feed, 'Feed')
  // vte.cxへリクエスト
  const method = 'PUT'
  const url = `${SERVLETPATH_PROVIDER}/?_signature`
  let response:Response
  try {
    response = await requestVtecx(method, url, req, JSON.stringify(feed))
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext putSignatures] response=${response}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  return await getJson(response)
}

/**
 * delete the signature.
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param uri key
 * @param revision revision
 * @return true if successful
 */
 export const deleteSignature = async (req:IncomingMessage, res:ServerResponse, uri:string, revision?:number): Promise<boolean> => {
  //console.log('[vtecxnext deleteSignature] start.')
  // キー入力値チェック
  checkUri(uri)
  // vte.cxへリクエスト
  const method = 'DELETE'
  const url = `${SERVLETPATH_PROVIDER}${uri}?_signature${revision ? '&r=' + revision : ''}`
  let response:Response
  try {
    response = await requestVtecx(method, url, req)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext deleteSignature] response=${response}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  return true
}

/**
 * check the signature.
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param uri key
 * @return true if the signature is valid
 */
 export const checkSignature = async (req:IncomingMessage, res:ServerResponse, uri:string): Promise<boolean> => {
  //console.log('[vtecxnext checkSignature] start.')
  // キー入力値チェック
  checkUri(uri)
  // vte.cxへリクエスト
  const method = 'GET'
  const url = `${SERVLETPATH_PROVIDER}${uri}?_signature`
  let response:Response
  try {
    response = await requestVtecx(method, url, req)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext checkSignature] response=${response}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  return true
}

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
 export const sendMail = async (req:IncomingMessage, res:ServerResponse, entry:any, to:string[], cc?:string[], bcc?:string[], attachments?:string[]): Promise<boolean> => {
  //console.log(`[vtecxnext sendMail] start. to=${to}`)
  // 入力チェック
  checkNotNull(entry, 'Entry')
  // 引数編集
  let links:any[] = []
  const linksTo = getLinks('to', to)
  //console.log(`[vtecxnext sendMail] linksTo=${JSON.stringify(linksTo)}`)
  if (linksTo) {
    links = links.concat(linksTo)
  }
  if (cc) {
    const linksCc = getLinks('cc', cc)
    if (linksCc) {
      links = links.concat(linksCc)
    }
  }
  if (bcc) {
    const linksBcc = getLinks('bcc', bcc)
    if (linksBcc) {
      links = links.concat(linksBcc)
    }
  }
  if (attachments) {
    const linksAttachments = getLinks('attachment', attachments)
    if (linksAttachments) {
      links = links.concat(linksAttachments)
    }
  }
  //console.log(`[vtecxnext sendMail] links = ${JSON.stringify(links)}`)
  let feed = {'feed' : {'entry' : [entry], 'link' : links}}
  //console.log(`[vtecxnext sendMail] feed = ${JSON.stringify(feed)}`)
  // vte.cxへリクエスト
  const method = 'POST'
  const url = `${SERVLETPATH_PROVIDER}/?_sendmail`
  let response:Response
  try {
    response = await requestVtecx(method, url, req, JSON.stringify(feed))
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext sendMail] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  return true
}

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
 export const pushNotification = async (req:IncomingMessage, res:ServerResponse, message:string, to:string[], title?:string, subtitle?:string, imageUrl?:string, data?:any): Promise<boolean> => {
  //console.log(`[vtecxnext pushNotification] start. to=${to}`)
  // 入力チェック
  checkNotNull(message, 'Message')
  checkNotNull(to, 'Destination')
  // 引数編集
  const links:any[] = []
  for (const destination of to) {
    const link = {'___rel' : 'to', '___href' : destination}
    links.push(link)
  }
  const categories:any[] = []
  if (imageUrl) {
    const category = {'___scheme' : 'imageurl', '___label' : imageUrl}
    categories.push(category)
  }
  if (data) {
    for (const name in data) {
      const category = {'___scheme' : name, '___label' : data[name]}
      categories.push(category)
    }
  }
  const content = {'______text' : message}
  const entry:any = {}
  if (title) {
    entry['title'] = title
  }
  if (subtitle) {
    entry['subtitle'] = subtitle
  }
  entry['content'] = content
  if (categories) {
    entry['category'] = categories
  }
  const feed = {'feed' : {
    'entry' : [entry],
    'link' : links}
  }
  //console.log(`[vtecxnext pushNotification] feed = ${JSON.stringify(feed)}`)
  // vte.cxへリクエスト
  const method = 'POST'
  const url = `${SERVLETPATH_PROVIDER}/?_pushnotification`
  let response:Response
  try {
    response = await requestVtecx(method, url, req, JSON.stringify(feed))
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext pushNotification] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  return true
}

/**
 * set status of MessageQueue.
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param flag true if on, false if off
 * @param channel channel
 */
 export const setMessageQueueStatus = async (req:IncomingMessage, res:ServerResponse, flag:boolean, channel:string): Promise<boolean> => {
  //console.log(`[vtecxnext setMessageQueueStatus] start. channel=${channel} flag=${flag}`)
  // キー入力値チェック
  checkUri(channel)
  // vte.cxへリクエスト
  const method = 'PUT'
  const url = `${SERVLETPATH_PROVIDER}${channel}?_mqstatus=${flag ? 'true' : 'false'}`
  let response:Response
  try {
    response = await requestVtecx(method, url, req)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext setMessageQueueStatus] response=${response}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  return true
}

/**
 * set MessageQueue.
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param feed entries (JSON)
 * @param channel channel
 * @return true if successful
 */
 export const setMessageQueue = async (req:IncomingMessage, res:ServerResponse, feed:any, channel:string): Promise<boolean> => {
  //console.log(`[vtecxnext setMessageQueue] start. channel=${channel} feed=${feed}`)
  // 入力チェック
  checkUri(channel)
  checkNotNull(feed, 'Feed')
  // vte.cxへリクエスト
  const method = 'POST'
  const url = `${SERVLETPATH_PROVIDER}${channel}?_mq`
  let response:Response
  try {
    response = await requestVtecx(method, url, req, JSON.stringify(feed))
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext setMessageQueue] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  return true
}

/**
 * get feed from session
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param name name
 * @return feed
 */
 export const getMessageQueue = async (req:IncomingMessage, res:ServerResponse, channel:string): Promise<any> => {
  //console.log(`[vtecxnext getMessageQueue] start. channel=${channel}`)
  // 入力チェック
  checkUri(channel)
  // vte.cxへリクエスト
  const method = 'GET'
  const url = `${SERVLETPATH_PROVIDER}${channel}?_mq`
  let response:Response
  try {
    response = await requestVtecx(method, url, req)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext getMessageQueue] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  return await getJson(response)
}

/**
 * join to the group
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param group group
 * @param selfid hierarchical name under my group alias
 * @return feed
 */
 export const joinGroup = async (req:IncomingMessage, res:ServerResponse, group:string, selfid:string): Promise<any> => {
  //console.log(`[vtecxnext joinGroup] start. group=${group} selfid=${selfid}`)
  // 入力チェック
  checkUri(group)
  checkNotNull(selfid, 'selfid (hierarchical name under my group alias)')
  // vte.cxへリクエスト
  const method = 'PUT'
  const url = `${SERVLETPATH_PROVIDER}${group}?_joingroup&_selfid=${selfid}`
  let response:Response
  try {
    response = await requestVtecx(method, url, req)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext joinGroup] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  return await getJson(response)
}

/**
 * leave from the group
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param group group
 * @return feed
 */
 export const leaveGroup = async (req:IncomingMessage, res:ServerResponse, group:string): Promise<boolean> => {
  //console.log(`[vtecxnext leaveGroup] start. group=${group}`)
  // 入力チェック
  checkUri(group)
  // vte.cxへリクエスト
  const method = 'DELETE'
  const url = `${SERVLETPATH_PROVIDER}${group}?_leavegroup`
  let response:Response
  try {
    response = await requestVtecx(method, url, req)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext leaveGroup] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  return true
}

/**
 * Get entries that have entries in a group, but are not in the group.
 * (for entries with no signature or with an incorrect signature, if the user group requires a signature)
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param uri group key
 * @return feed (entry array)
 */
export const noGroupMember = async (req:IncomingMessage, res:ServerResponse, uri:string): Promise<any> => {
  //console.log('[vtecxnext noGroupMember] start.')
  // キー入力値チェック
  checkUri(uri)
  // vte.cxへリクエスト
  const method = 'GET'
  const url = `${SERVLETPATH_DATA}${uri}?_no_group_member`
  let response:Response
  try {
    response = await requestVtecx(method, url, req)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext noGroupMember] response=${response}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  return await getJson(response)
}

/**
 * Get groups
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param uri group key
 * @return feed (entry array)
 */
export const getGroups = async (req:IncomingMessage, res:ServerResponse): Promise<any> => {
  //console.log('[vtecxnext getGroups] start.')
  // vte.cxへリクエスト
  const method = 'GET'
  const url = `${SERVLETPATH_DATA}/?_group`
  let response:Response
  try {
    response = await requestVtecx(method, url, req)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext getGroups] response=${response}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  return await getJson(response)
}

/**
 * whether you are in the group
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param uri group key
 * @return true/false 
 */
export const isGroupMember = async (req:IncomingMessage, res:ServerResponse, uri:string): Promise<boolean> => {
  //console.log('[vtecxnext noGroupMember] start.')
  // キー入力値チェック
  checkUri(uri)
  // vte.cxへリクエスト
  const method = 'GET'
  const url = `${SERVLETPATH_DATA}${uri}?_is_group_member`
  let response:Response
  try {
    response = await requestVtecx(method, url, req)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext noGroupMember] response=${response}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  const data = await getJson(response)
  return data?.feed?.title === 'true' ? true : false
}

/**
 * whether you are in the admin group
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @return true/false 
 */
export const isAdmin = async (req:IncomingMessage, res:ServerResponse): Promise<boolean> => {
  return await isGroupMember(req, res, '/_group/$admin')
}

/**
 * add user
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param feed entry (JSON)
 * @param reCaptchaToken reCAPTCHA token
 * @return message feed
 */
export const adduser = async (req:IncomingMessage, res:ServerResponse, feed:any, reCaptchaToken:string): Promise<any> => {
  //console.log(`[vtecxnext adduser] start. feed=${feed}`)
  // 入力チェック
  checkNotNull(feed, 'Feed')
  // vte.cxへリクエスト
  const method = 'POST'
  const param = reCaptchaToken ? `&g-recaptcha-token=${reCaptchaToken}` : ''
  const url = `${SERVLETPATH_DATA}/?_adduser${param}`
  let response:Response
  try {
    response = await requestVtecx(method, url, req, JSON.stringify(feed))
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext adduser] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  return await getJson(response)
}

/**
 * add user by user admin
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param feed entries (JSON)
 * @param reCaptchaToken reCAPTCHA token
 * @return message feed
 */
export const adduserByAdmin = async (req:IncomingMessage, res:ServerResponse, feed:any): Promise<any> => {
  //console.log(`[vtecxnext adduserByAdmin] start. feed=${feed}`)
  // 入力チェック
  checkNotNull(feed, 'Feed')
  // vte.cxへリクエスト
  const method = 'POST'
  const url = `${SERVLETPATH_DATA}/?_adduserByAdmin`
  let response:Response
  try {
    response = await requestVtecx(method, url, req, JSON.stringify(feed))
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext adduserByAdmin] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  return await getJson(response)
}

/**
 * Send email for password reset
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param feed entry (JSON)
 * @param reCaptchaToken reCAPTCHA token
 * @return message feed
 */
export const passreset = async (req:IncomingMessage, res:ServerResponse, feed:any, reCaptchaToken?:string): Promise<any> => {
  //console.log(`[vtecxnext passreset] start. feed=${feed}`)
  // 入力チェック
  checkNotNull(feed, 'Feed')
  // vte.cxへリクエスト
  const method = 'POST'
  const param = reCaptchaToken ? `&g-recaptcha-token=${reCaptchaToken}` : ''
  const url = `${SERVLETPATH_DATA}/?_passreset${param}`
  let response:Response
  try {
    response = await requestVtecx(method, url, req, JSON.stringify(feed))
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext passreset] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  return await getJson(response)
}

/**
 * change password
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param feed entry (JSON)
 * @return message feed
 */
export const changepass = async (req:IncomingMessage, res:ServerResponse, feed:any): Promise<any> => {
  //console.log(`[vtecxnext changepass] start. feed=${feed}`)
  // 入力チェック
  checkNotNull(feed, 'Feed')
  // vte.cxへリクエスト
  const method = 'PUT'
  const url = `${SERVLETPATH_DATA}/?_changephash`
  let response:Response
  try {
    response = await requestVtecx(method, url, req, JSON.stringify(feed))
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext changepass] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  return await getJson(response)
}

/**
 * change password by user admin
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param feed entry (JSON)
 * @return message feed
 */
export const changepassByAdmin = async (req:IncomingMessage, res:ServerResponse, feed:any): Promise<any> => {
  //console.log(`[vtecxnext changepassByAdmin] start. feed=${feed}`)
  // 入力チェック
  checkNotNull(feed, 'Feed')
  // vte.cxへリクエスト
  const method = 'PUT'
  const url = `${SERVLETPATH_DATA}/?_changephashByAdmin`
  let response:Response
  try {
    response = await requestVtecx(method, url, req, JSON.stringify(feed))
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext changepassByAdmin] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  return await getJson(response)
}

/**
 * change login user's account
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param feed entries (JSON)
 * @return message feed
 */
export const changeaccount = async (req:IncomingMessage, res:ServerResponse, feed:any): Promise<any> => {
  //console.log(`[vtecxnext changeaccount] start. feed=${feed}`)
  // 入力チェック
  checkNotNull(feed, 'Feed')
  // vte.cxへリクエスト
  const method = 'PUT'
  const url = `${SERVLETPATH_DATA}/?_changeaccount`
  let response:Response
  try {
    response = await requestVtecx(method, url, req, JSON.stringify(feed))
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext changeaccount] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  return await getJson(response)
}

/**
 * verify to change login user's account
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param verifyCode verify code
 * @return message feed
 */
export const changeaccount_verify = async (req:IncomingMessage, res:ServerResponse, verifyCode:string): Promise<any> => {
  //console.log(`[vtecxnext changeaccount_verify] start. verifyCode=${verifyCode}`)
  // 入力値チェック
  checkNotNull(verifyCode, 'verify code')
  // vte.cxへリクエスト
  const method = 'PUT'
  const url = `${SERVLETPATH_DATA}/?_changeaccount_verify=${verifyCode}`
  let response:Response
  try {
    response = await requestVtecx(method, url, req)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext changeaccount_verify] response=${response}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  return await getJson(response)
}

/**
 * get user status
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param account account
 * @return user status
 */
export const userstatus = async (req:IncomingMessage, res:ServerResponse, account?:string): Promise<any> => {
  //console.log('[vtecxnext userstatus] start.')
  // vte.cxへリクエスト
  const method = 'GET'
  const url = `${SERVLETPATH_DATA}/?_userstatus${account ? '=' + account : ''}`
  let response:Response
  try {
    response = await requestVtecx(method, url, req)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext userstatus] response=${response}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  return await getJson(response)
}

/**
 * revoke user
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param account account
 * @return message feed
 */
export const revokeuser = async (req:IncomingMessage, res:ServerResponse, account:string): Promise<any> => {
  //console.log('[vtecxnext revokeuser] start.')
  // 入力値チェック
  checkNotNull(account, 'account')
  // vte.cxへリクエスト
  const method = 'PUT'
  const url = `${SERVLETPATH_DATA}/?_revokeuser=${account}`
  let response:Response
  try {
    response = await requestVtecx(method, url, req)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext revokeuser] response=${response}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  return await getJson(response)
}

/**
 * revoke users
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param feed entries (JSON)
 * @return message feed
 */
export const revokeusers = async (req:IncomingMessage, res:ServerResponse, feed:any): Promise<any> => {
  //console.log(`[vtecxnext revokeusers] start. feed=${feed}`)
  // 入力チェック
  checkNotNull(feed, 'Feed')
  // vte.cxへリクエスト
  const method = 'PUT'
  const url = `${SERVLETPATH_DATA}/?_revokeuser`
  let response:Response
  try {
    response = await requestVtecx(method, url, req, JSON.stringify(feed))
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext revokeusers] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  return await getJson(response)
}

/**
 * activate user
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param account account
 * @return message feed
 */
export const activateuser = async (req:IncomingMessage, res:ServerResponse, account:string): Promise<any> => {
  //console.log('[vtecxnext activateuser] start.')
  // 入力値チェック
  checkNotNull(account, 'account')
  // vte.cxへリクエスト
  const method = 'PUT'
  const url = `${SERVLETPATH_DATA}/?_activateuser=${account}`
  let response:Response
  try {
    response = await requestVtecx(method, url, req)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext activateuser] response=${response}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  return await getJson(response)
}

/**
 * activate users
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param feed entries (JSON)
 * @return message feed
 */
export const activateusers = async (req:IncomingMessage, res:ServerResponse, feed:any): Promise<any> => {
  //console.log(`[vtecxnext activateusers] start. feed=${feed}`)
  // 入力チェック
  checkNotNull(feed, 'Feed')
  // vte.cxへリクエスト
  const method = 'PUT'
  const url = `${SERVLETPATH_DATA}/?_activateuser`
  let response:Response
  try {
    response = await requestVtecx(method, url, req, JSON.stringify(feed))
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext activateusers] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  return await getJson(response)
}

/**
 * cancel user.
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param account account
 * @return message feed
 */
export const canceluser = async (req:IncomingMessage, res:ServerResponse): Promise<any> => {
  //console.log('[vtecxnext canceluser] start.')
  // vte.cxへリクエスト
  const method = 'DELETE'
  const url = `${SERVLETPATH_DATA}/?_canceluser`
  let response:Response
  try {
    response = await requestVtecx(method, url, req)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext canceluser] response=${response}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  return await getJson(response)
}

/**
 * delete user
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param account account
 * @return message feed
 */
export const deleteuser = async (req:IncomingMessage, res:ServerResponse, account:string): Promise<any> => {
  //console.log('[vtecxnext deleteuser] start.')
  // 入力値チェック
  checkNotNull(account, 'account')
  // vte.cxへリクエスト
  const method = 'DELETE'
  const url = `${SERVLETPATH_DATA}/?_deleteuser=${account}`
  let response:Response
  try {
    response = await requestVtecx(method, url, req)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext deleteuser] response=${response}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  return await getJson(response)
}

/**
 * revoke users
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param feed entries (JSON)
 * @return message feed
 */
export const deleteusers = async (req:IncomingMessage, res:ServerResponse, feed:any): Promise<any> => {
  //console.log(`[vtecxnext deleteusers] start. feed=${feed}`)
  // 入力チェック
  checkNotNull(feed, 'Feed')
  // vte.cxへリクエスト
  const method = 'DELETE'
  const url = `${SERVLETPATH_DATA}/?_deleteuser`
  let response:Response
  try {
    response = await requestVtecx(method, url, req, JSON.stringify(feed))
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext deleteusers] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  return await getJson(response)
}

/**
 * save files
 * @param req request 
 * @param res respose (for authentication)
 * @param uri key
 * @returns message
 */
export const savefiles = async (req:IncomingMessage, res:ServerResponse, uri:string): Promise<any> => {
  //console.log(`[vtecxnext savefiles] start. uri=${uri}`)
  // キー入力値チェック
  checkUri(uri)

  //for (const key in req.headers) {
  //  //console.log(`[vtecxnext savefiles] [header] ${key}:${req.headers[key]}`)
  //}

  type FormidableFile = {
    field: string
    file: File
  }

  /* Get files using formidable */
  const formidableFiles = await new Promise<FormidableFile[] | undefined>((resolve, reject) => {
    const form = new formidable.IncomingForm()
    const files: FormidableFile[] = []
    form.on('file', (field, file) => {
      const partFile:FormidableFile = {'file': file, 'field': field}
      files.push(partFile)
    })
    form.on('end', () => resolve(files))
    form.on('error', err => reject(err))
    form.parse(req, () => {
        //
    })
  }).catch(e => {
    //console.log(e)
    throw new VtecxNextError(400, `${e}`)
  })

  //console.log(`[vtecxnext savefiles] formidableFiles.length=${formidableFiles ? formidableFiles.length : 0}`)

  if (!formidableFiles || formidableFiles.length < 1) {
    throw new VtecxNextError(400, `An upload file is required.`)
  }

  let contentUris:string = ''
  const promises:Promise<Response>[] = []
  for (const formidableFile of formidableFiles) {
    //console.log(`[vtecxnext savefiles] formidableFile field=${formidableFile.field} filepath=${formidableFile.file.filepath} size=${formidableFile.file.size} mymetype=${formidableFile.file.mimetype} newFilename=${formidableFile.file.newFilename} originalFilename=${formidableFile.file.originalFilename}`)
    const fileBuffer:Buffer = fs.readFileSync(formidableFile.file.filepath)
    fs.unlink(formidableFile.file.filepath, () => {
      //console.log(`[vtecxnext savefiles] fs.unlink: ${formidableFile.file.filepath}`)
    })

    // vte.cxへリクエスト
    const method = 'PUT'
    const contentUri = `${uri}${uri.endsWith('/') ? '' : '/'}${formidableFile.field}`
    const url = `${SERVLETPATH_PROVIDER}${contentUri}?_content`
    const headers = {'Content-Type' : formidableFile.file.mimetype}
    //console.log(`[vtecxnext savefiles] request. url=${url}`)
    const promiseResponse = requestVtecx(method, url, req, fileBuffer, headers)
    promises.push(promiseResponse)
    // 戻り値用
    contentUris += `${contentUris ? ', ' : ''}${contentUri}`
  }

  const msg:string = ''
  for (const promise of promises) {
    const response = await promise
    //console.log(`[vtecxnext savefiles] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    setCookie(response, res)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
  }
  return {'feed' : {'title' : contentUris}}

  /* API RouteでFormDataを使用するとうまくいかなかった。(リクエスト先の受信データサイズが0になる。)
  const formData = new FormData()
  if (formidableFiles?.length) {
    for (const formidableFile of formidableFiles) {
      //console.log(`[vtecxnext savefiles] formidableFile field=${formidableFile.field} filepath=${formidableFile.file.filepath} size=${formidableFile.file.size} mymetype=${formidableFile.file.mimetype} newFilename=${formidableFile.file.newFilename} originalFilename=${formidableFile.file.originalFilename}`)
      
      const buffer:Buffer = fs.readFileSync(formidableFile.file.filepath)
      const file:Blob = new Blob([buffer])

      //console.log(`[vtecxnext savefiles] file.size=${file.size} file.length=${file.length} file.name=${file.name} file.type=${file.type}`)

      formData.append(formidableFile.field, file, formidableFile.file.originalFilename ? formidableFile.file.originalFilename : undefined)
    }
  }

  // vte.cxへリクエスト
  const method = 'POST'
  const url = `${SERVLETPATH_PROVIDER}${uri}?_content`
  //console.log(`[vtecxnext savefiles] request. url=${url}`)
  const response = await requestVtecx(method, url, req, formData)
  //console.log(`[vtecxnext savefiles] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  return await getJson(response)
  */

}

/**
 * upload content
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param uri key
 * @return message
 */
export const putcontent = async (req:IncomingMessage, res:ServerResponse, uri:string): Promise<any> => {
  //console.log(`[vtecxnext putcontent] start. uri=${uri} content-type:${req.headers['content-type']} content-length:${req.headers['content-length']}`)
  // キー入力値チェック
  checkUri(uri)
  // vte.cxへリクエスト
  const method = 'PUT'
  const url = `${SERVLETPATH_PROVIDER}${uri}?_content`
  //const headers = {'Content-Type' : req.headers['content-type'], 'Content-Length' : req.headers['content-length']}
  const headers = {'Content-Type' : req.headers['content-type']}
  const buf = await buffer(req)
  let response:Response
  try {
    response = await requestVtecx(method, url, req, buf, headers)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext putcontent] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  return await getJson(response)
}

/**
 * delete content
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param uri key
 * @return message
 */
export const deletecontent = async (req:IncomingMessage, res:ServerResponse, uri:string): Promise<any> => {
  //console.log(`[vtecxnext deletecontent] start. uri=${uri}`)
  // キー入力値チェック
  checkUri(uri)
  // vte.cxへリクエスト
  const method = 'DELETE'
  const url = `${SERVLETPATH_PROVIDER}${uri}?_content`
  let response:Response
  try {
    response = await requestVtecx(method, url, req)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext deletecontent] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  return await getJson(response)
}

/**
 * get content.
 * Writes a content to the response.
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param uri key
 * @return true
 */
export const getcontent = async (req:IncomingMessage, res:ServerResponse, uri:string): Promise<boolean> => {
  //console.log(`[vtecxnext getcontent] start. uri=${uri}`)
  // キー入力値チェック
  checkUri(uri)
  // vte.cxへリクエスト
  const method = 'GET'
  const url = `${SERVLETPATH_PROVIDER}${uri}?_content`
  let response:Response
  try {
    response = await requestVtecx(method, url, req)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext getcontent] response. status=${response.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  //console.log(`[vtecxnext getcontent] setCookie end.`)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  //console.log(`[vtecxnext getcontent] checkVtecxResponse end.`)
  // 戻り値
  const resData = await response.blob()
  setResponseHeaders(response, res)
  res.statusCode = response.status
  if (response.status !== 204) {
    const csvData:ArrayBuffer = await resData.arrayBuffer()
    res.end(new Uint8Array(csvData))
  } else {
    res.end()
  }
  return true
}

/**
 * add acl
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param feed entries
 * @return message
 */
 export const addacl = async (req:IncomingMessage, res:ServerResponse, feed:any): Promise<any> => {
  //console.log('[vtecxnext addacl] start.')
  // 入力チェック
  checkNotNull(feed, 'Feed')
  // vte.cxへリクエスト
  const method = 'PUT'
  const url = `${SERVLETPATH_DATA}/?_addacl`
  let response:Response
  try {
    response = await requestVtecx(method, url, req, JSON.stringify(feed))
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext addacl] response=${response}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  return await getJson(response)
}

/**
 * remove acl
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param feed entries
 * @return message
 */
export const removeacl = async (req:IncomingMessage, res:ServerResponse, feed:any): Promise<any> => {
  //console.log('[vtecxnext removeacl] start.')
  // 入力チェック
  checkNotNull(feed, 'Feed')
  // vte.cxへリクエスト
  const method = 'PUT'
  const url = `${SERVLETPATH_DATA}/?_removeacl`
  let response:Response
  try {
    response = await requestVtecx(method, url, req, JSON.stringify(feed))
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext removeacl] response=${response}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  return await getJson(response)
}

/**
 * add alias
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param feed entries
 * @return message
 */
export const addalias = async (req:IncomingMessage, res:ServerResponse, feed:any): Promise<any> => {
  //console.log('[vtecxnext addalias] start.')
  // 入力チェック
  checkNotNull(feed, 'Feed')
  // vte.cxへリクエスト
  const method = 'PUT'
  const url = `${SERVLETPATH_DATA}/?_addalias`
  let response:Response
  try {
    response = await requestVtecx(method, url, req, JSON.stringify(feed))
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext addalias] response=${response}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  return await getJson(response)
}

/**
 * remove alias
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param feed entries
 * @return message
 */
export const removealias = async (req:IncomingMessage, res:ServerResponse, feed:any): Promise<any> => {
  //console.log('[vtecxnext removealias] start.')
  // 入力チェック
  checkNotNull(feed, 'Feed')
  // vte.cxへリクエスト
  const method = 'PUT'
  const url = `${SERVLETPATH_DATA}/?_removealias`
  let response:Response
  try {
    response = await requestVtecx(method, url, req, JSON.stringify(feed))
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext removealias] response=${response}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  return await getJson(response)
}

/**
 * OAuth authorization request to LINE
 * @param req request (for authentication)
 * @param res response (for authentication)
 */
export const oauthLine = async (req:IncomingMessage, res:ServerResponse): Promise<boolean> => {
  const provider = 'line'
  const oauthUrl = 'https://access.line.me/oauth2/v2.1/authorize'
  return await oauth(req, res, provider, oauthUrl)
}

/**
 * OAuth authorization request to LINE
 * @param req request (for authentication)
 * @param res response (for authentication)
 */
export const oauthCallbackLine = async (req:IncomingMessage, res:ServerResponse): Promise<boolean> => {
  // OAuthアクセストークン、OAuth情報を取得
  const provider = 'line'
  const accesstokenUrl = 'https://api.line.me/oauth2/v2.1/token'
  const oauthInfo = await oauthGetAccesstoken(req, res, provider, accesstokenUrl)

  // ユーザ識別情報を取得
  const userInfo = await oauthGetUserinfoLine(req, res, oauthInfo)

  // vte.cxユーザと連携・ログイン
  await oauthLink(req, res, provider, userInfo)
  return true
}

/**
 * get binary data from stream
 * @param readable Readable
 * @returns buffer
 */
export const buffer = async (readable: Readable):Promise<Buffer> => {
  const chunks = []
  for await (const chunk of readable) {
    chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk)
  }
  return Buffer.concat(chunks)
}

/**
 * get TOTP link
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param chs length of one side of QR code
 * @return QR code URL in feed.title
 */
export const getTotpLink = async (req:IncomingMessage, res:ServerResponse, chs?:number): Promise<any> => {
  //console.log('[vtecxnext getTotpLink] start.')
  // vte.cxへリクエスト
  const method = 'POST'
  const url = `${SERVLETPATH_DATA}/?_createtotp${chs ? '&_chs=' + String(chs) : ''}`
  let response:Response
  try {
    response = await requestVtecx(method, url, req)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext getTotpLink] response=${response}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  return await getJson(response)
}

/**
 * create TOTP
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param feed one-time password for feed.title when you do book registration
 * @return message
 */
export const createTotp = async (req:IncomingMessage, res:ServerResponse, feed:any): Promise<any> => {
  //console.log('[vtecxnext createTotp] start.')
  // 入力チェック
  checkNotNull(feed, 'Feed')
  // vte.cxへリクエスト
  const method = 'POST'
  const url = `${SERVLETPATH_DATA}/?_createtotp`
  let response:Response
  try {
    response = await requestVtecx(method, url, req, JSON.stringify(feed))
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext createTotp] response=${response}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  return await getJson(response)
}

/**
 * delete TOTP
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param account target account (for service admin user)
 * @return message
 */
export const deleteTotp = async (req:IncomingMessage, res:ServerResponse, account?:string): Promise<any> => {
  //console.log('[vtecxnext deleteTotp] start.')
  // vte.cxへリクエスト
  const method = 'DELETE'
  const url = `${SERVLETPATH_DATA}/?_deletetotp${account ? '=' + account : ''}`
  let response:Response
  try {
    response = await requestVtecx(method, url, req)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext deleteTotp] response=${response}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  return await getJson(response)
}

/**
 * change TDID (Trusted device ID)
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param account target account (for service admin user)
 * @return message
 */
export const changeTdid = async (req:IncomingMessage, res:ServerResponse): Promise<any> => {
  //console.log('[vtecxnext changeTdid] start.')
  // vte.cxへリクエスト
  const method = 'PUT'
  const url = `${SERVLETPATH_DATA}/?_changetdid`
  let response:Response
  try {
    response = await requestVtecx(method, url, req)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext changeTdid] response=${response}`)
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  return await getJson(response)
}



//---------------------------------------------
/**
 * response class
 */
export class VtecxResponse {
  status:number
  header:any
  data:any
  constructor(status:number, header:any, data:any) {
    this.status = status
    this.header = header
    this.data = data
  }
}

/**
 * Error returned from vte.cx
 */
export class VtecxNextError extends Error {
  status:number
  constructor(status:number, message:string) {
    super(message)
    this.name = 'VtecxNextError'
    this.status = status
  }
}

/**
 * Fetch Error
 */
export class FetchError extends VtecxNextError {
  //url:string
  //requestInit:RequestInit
  constructor(message:string) {
    super(500, message)
    this.name = 'FetchError'
    //this.url = url
    //this.requestInit = requestInit
  }
}

//---------------------------------------------
/**
 * vte.cxへリクエスト
 * @param method メソッド
 * @param url サーブレットパス以降のURL
 * @param req リクエスト。認証情報設定に使用。
 * @param body リクエストデータ
 * @param additionalHeaders リクエストヘッダ追加分
 * @param targetService 連携サービス名
 * @param mode RequestMode ("cors" | "navigate" | "no-cors" | "same-origin")
 * @returns promise
 */
const requestVtecx = async (method:string, url:string, req?:IncomingMessage, body?:any, additionalHeaders?:any, targetService?:string, mode?:RequestMode): Promise<Response> => {
  // cookieの値をvte.cxへのリクエストヘッダに設定
  const cookie = req ? req.headers['cookie'] : undefined
  const headers:any = cookie ? {'Cookie' : cookie} : {}
  if (additionalHeaders) {
    for (const key in additionalHeaders) {
      headers[key] = additionalHeaders[key]
    }
  }
  if (targetService) {
    // サービス連携の場合
    const servicekey = process.env[`SERVICEKEY_${targetService}`]
    //console.log(`[requestVtecx] targetService=${targetService} servicekey=${servicekey}`)
    if (servicekey) {
      headers['X-SERVICELINKAGE'] = targetService
      headers['X-SERVICEKEY'] = servicekey
    }
  }
  return fetchVtecx(method, url, headers, body, mode)
}

/**
 * vte.cxへリクエスト
 * @param method メソッド
 * @param url サーブレットパス以降のURL
 * @param headers リクエストヘッダ。連想配列で指定。
 * @param body リクエストデータ
 * @param mode RequestMode ("cors" | "navigate" | "no-cors" | "same-origin")
 * @returns promise
 */
const fetchVtecx = async (method:string, url:string, headers:any, body?:any, mode?:RequestMode): Promise<Response> => {
  //console.log(`[vtecxnext fetchVtecx] url=${process.env.VTECX_URL}${url}`)
  headers['X-Requested-With'] = 'XMLHttpRequest'
  if (VTECX_SERVICENAME) {
    headers['X-SERVICENAME'] = VTECX_SERVICENAME
  }
  const apiKey = process.env.VTECX_APIKEY
  if (apiKey && !url.startsWith(SERVLETPATH_DATA)) {
    //headers['Authorization'] = `APIKey ${apiKey}`
    const apiKeyVal = `APIKey ${apiKey}`
    if (headers.Authorization) {
      if (Array.isArray(headers.Authorization)) {
        headers.Authorization.push(apiKeyVal)
      } else {
        const tmp = headers.Authorization
        headers.Authorization = [tmp, apiKeyVal]
      }
    } else {
      headers.Authorization = apiKeyVal
    }
  }
  //console.log(`[vtecxnext fetchVtecx] headers = ${JSON.stringify(headers)}`)
  const requestInit:RequestInit = {
    body: body,
    method: method,
    headers: headers
  }
  if (mode) {
    requestInit['mode'] = mode
  }
  
  return fetchProc(`${VTECX_URL}${url}`, requestInit)
}

/** vte.cx URL */
const VTECX_URL = process.env.VTECX_URL ?? ''
const VTECX_SERVICENAME = process.env.VTECX_SERVICENAME ?? ''

const newFetchError = (e:any, isVtecx:boolean):FetchError => {
  let errMsg:string
  if (e instanceof Error) {
    const errName = isVtecx ? 'VtecxFetchError' : 'FetchError'
    errMsg = `${errName}: ${e.message}`
  } else {
    errMsg = `Unexpected error.`
  }
  //console.log(`[vtecxnext fetchProc] errMsg = ${errMsg}`)
  return new FetchError(errMsg)
}

/**
 * fetch処理。try-catchを行う。
 * @param url URL
 * @param requestInit RequestInit
 * @returns Promise
 */
const fetchProc = (url:string, requestInit:RequestInit): Promise<Response> => {
  //console.log(`[vtecxnext fetchProc] url=${url}`)
  return fetch(url, requestInit)
}

/**
 * vte.cxからのset-cookieを、ブラウザへレスポンスする。
 * @param response vte.cxからのレスポンス
 * @param res ブラウザへのレスポンス
 */
const setCookie = (response:Response, res:ServerResponse): void => {
  // 各レスポンスヘッダーについて、ヘッダー名をキーとする配列をログ出力します。
  let setCookieVal = response.headers.get('set-cookie')
  if (setCookieVal === '' || setCookieVal) {
    //console.log(`[vtecxnext setCookie] value : ${setCookieVal}`)
    //res.setHeader('set-cookie', setCookieVal)
    const setCookieVals = splitCookieValue(setCookieVal)
    //console.log(`[vtecxnext setCookie] values : ${setCookieVals}`)
    res.setHeader('set-cookie', setCookieVals)
  }
}

/**
 * 複数のset-cookieの値を分割。
 * fetchで受け取った際カンマ区切りで繋げられており、
 * これをそのままset-cookieにセットするとブラウザでは2項目目以降が適用されないため。
 * @param val set-cookieの値
 * @returns 分割したset-cookieの値
 */
const splitCookieValue = (val:string):string[] => {
  //console.log(`[vtecxnext splitCookieValue] start. val = ${val}`)

  const ret = []
  if (val) {
    const parts = val.split(', ')
    let tmp:string = ''
    for (const part of parts) {
      tmp += part
      // ; Expires=Thu, 09-Mar-2023 06:55:48 GMT 等のカンマは区切りとしない。
      if (part.match('^.*; Expires=...$')) {
        // 続きあり
      } else {
        ret.push(tmp)
        tmp = ''
      }
    }
    if (tmp) {
      ret.push(tmp)
    }
  }

  //console.log(`[vtecxnext splitCookieValue] return : ${JSON.stringify(ret)}`)
  return ret
}

/**
 * vte.cxからのallow-originを、ブラウザへレスポンスする。
 * @param response vte.cxからのレスポンス
 * @param res ブラウザへのレスポンス
 */
const setAllowOrigin = (response:Response, res:ServerResponse): void => {
  let val = response.headers.get('access-control-allow-origin')
  val ? res.setHeader('access-control-allow-origin', val) : ''
  val = response.headers.get('access-control-allow-methods')
  val ? res.setHeader('access-control-allow-methods', val) : ''
  val = response.headers.get('access-control-allow-headers')
  val ? res.setHeader('access-control-allow-headers', val) : ''
  val = response.headers.get('access-control-allow-credentials')
  val ? res.setHeader('access-control-allow-credentials', val) : ''
}

/**
 * vte.cxからのレスポンスヘッダを、ブラウザへレスポンスする。
 * コンテンツの戻し時に使用。
 * @param response vte.cxからのレスポンス
 * @param res ブラウザへのレスポンス
 */
const setResponseHeaders = (response:Response, res:ServerResponse): void => {
  const it = response.headers.entries()
  let header:IteratorResult<[string, string], any> = it.next()
  while (header && !header.done) {
    const name = header.value[0]
    if (name.startsWith('content-') || name.startsWith('x-')) {
      const val = header.value[1]
      //console.log(`[setResponseHeaders] ${name} = ${val}`)
      res.setHeader(name, val)
    }
    header = it.next()
  }
}

/**
 * vte.cxからのレスポンスが正常かエラーかをチェックする。
 * エラーの場合 VtecxNextError をスローする。
 * @param response Response
 * @returns 戻り値はなし。エラーの場合VtecxNextErrorをスロー。
 */
const checkVtecxResponse = async (response:Response): Promise<void> => {
  if (response.status < 400 && response.status !== 203) {
    return
  } else {
    // エラー
    const data = await response.json()
    let message
    if (data && data.feed) {
      message = data.feed.title
    }
    message = message ?? `status=${response.status}`
    throw new VtecxNextError(response.status, message)
  }
}

/**
 * 入力チェック
 * エラーの場合 VtecxNextError をスローする。
 * @param val チェック値
 * @param name 項目名。エラーの場合メッセージに使用。
 * @returns 戻り値はなし。エラーの場合VtecxNextErrorをスロー。
 */
const checkNotNull = (val:any, name?:string): void => {
  if (!val) {
    throw new VtecxNextError(400, `${name ?? 'Key'} is required.`)
  }
}

/**
 * キーチェック。
 * 入力チェックと、先頭が/で始まっているかどうかチェックする。
 * エラーの場合 VtecxNextError をスローする。
 * @param str チェック値
 * @param name 項目名。エラーの場合メッセージに使用。
 * @returns 戻り値はなし。エラーの場合VtecxNextErrorをスロー。
 */
 const checkUri = (str:string, name?:string): void => {
  checkNotNull(str, name)
  if (!str.startsWith('/')) {
    throw new VtecxNextError(400, `${name ?? 'Key'} must start with a slash.`)
  }
}

/**
 * レスポンスデータをJSON形式で取得.
 * @param response レスポンス
 * @returns JSON
 */
const getJson = async (response:Response): Promise<any> => {
  // ステータスが204の場合nullを返す。
  if (response.status === 204) {
    return null
  }
  try {
    return await response.json()
  } catch (e) {
    let errMsg:string
    if (e instanceof Error) {
      //console.log(`[vtecxnext getJson] Error occured. ${e.name}: ${e.message}`)
      errMsg = `JsonError: ${e.message}`
    } else {
      errMsg = `JsonError: unexpected error`
    }
    throw new VtecxNextError(500, errMsg)
  }
}

/**
 * BigQuery登録・削除時のテーブル名指定文字列を編集
 * @param tablenames テーブル名(キー:entry第一階層名、値:テーブル名)
 * @returns BigQuery登録・削除時のテーブル名指定文字列 ({スキーマ第一階層名}:{テーブル名}, ...)
 */
const editBqTableNames = (tablenames:any): any => {
  //console.log(`[editBqTableNames] tablenames = ${tablenames}`)
  if (!tablenames) {
    return null
  }
  let result = ''
  for (const key in tablenames) {
    const value = tablenames[key]
    //console.log(`[editBqTableNames] ${key}=${value}`)
    result = `${result ? result + ',' : ''}${key}:${value}` 
  }
  //console.log(`[editBqTableNames] result=${result}`)
  return result
}

/**
 * BigQuery検索の引数を生成
 * @param sql SQL
 * @param values SQLに指定する値
 * @param parent 戻り値JSONの親項目(任意)か、CSVのヘッダ(任意)
 * @returns BigQuery検索の引数
 */
const editGetBqArgument = (sql:string, values?:any[], parent?:string): any => {
  // SQLに引数を代入（SQLインジェクション対応）
  const editSql = values ? formatSql(sql, values) : sql
  //console.log(`[vtecxnext editGetBqArgument] sql=${editSql}`)
  // 引数
  const feed:any = {'feed' : {'title' : editSql}}
  if (parent) {
    feed.feed['subtitle'] = parent
  }
  return feed
}

/**
 * SQLの'?'を指定された引数に置き換える。（SQLインジェクション対応）
 * @param sql SQL
 * @param values 置き換え対象値
 * @returns 値が代入されたSQL
 */
const formatSql = (sql:string, values:any[]): string => {
  if (!values) {
    return sql
  }
  return SqlString.format(sql, values)
}

/**
 * linkの編集
 * @param rel relに指定する値 
 * @param hrefs hrefに指定する値のリスト
 * @returns link
 */
const getLinks = (rel:string, hrefs:string[]): any => {
  if (!rel || !hrefs) {
    return undefined
  }
  const links = []
  let idx = 0
  for (const href of hrefs) {
    const link = {'___rel' : rel, '___href' : href}
    links[idx] = link
    idx++
  }
  //console.log(`[vtecxnext getLinks] links=${JSON.stringify(links)}`)
  return links
}

/**
 * OAuth authorization request
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param provider OAuth provider name
 * @param oauthUrl OAuth authorization request url
 * @return true
 */
const oauth = async (req:IncomingMessage, res:ServerResponse, provider:string, oauthUrl:string): Promise<boolean> => {
  //console.log(`[vtecxnext oauth] start. provider=${provider} oauthUrl=${oauthUrl}`)

  // TODO reCAPTCHAを必須とすべき。

  // 入力チェック
  checkNotNull(provider, 'OAuth provider')
  // vte.cxへリクエスト (state取得)
  const method = 'POST'
  const url = `${SERVLETPATH_OAUTH}/${provider}/create_state`
  let response:Response
  try {
    response = await requestVtecx(method, url, req)
  } catch (e) {
    throw newFetchError(e, true)
  }
  // レスポンスのエラーチェック
  await checkVtecxResponse(response)
  // 戻り値
  const data = await getJson(response)
  // state生成
  if (!data || !data.feed || !data.feed.title) {
    throw new VtecxNextError(401, `Could not generate state.`)
  }
  //console.log(`[vtecxnext oauth] response data=${JSON.stringify(data)}`)
  const state = data.feed.title
  const client_id = data.feed.subtitle
  const redirect_uri = data.feed.link[0].___href
  //const origin = getOrigin(oauthUrl)
  // 認可リクエストリダイレクトURL生成
  //console.log(`[vtecxnext oauth] redirect_uri=${redirect_uri}`)
  //console.log(`[vtecxnext oauth] origin=${origin}`)
  const authorizationUrl = `${oauthUrl}?response_type=code&client_id=${client_id}&redirect_uri=${encodeURI(redirect_uri)}&state=${state}&scope=profile`
  //console.log(`[vtecxnext oauth] authorizationUrl=${authorizationUrl}`)
  res.setHeader('Location', authorizationUrl)
  //res.setHeader('Access-Control-Allow-Origin', origin)
  //res.setHeader('Access-Control-Allow-Method', 'GET, OPTIONS')
  //console.log(`[vtecxnext oauth] response headers=${JSON.stringify(res.getHeaders())}`)
  res.writeHead(302)
  res.end()
  return true
}

/**
 * OAuth authorization request
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param provider OAuth provider name
 * @param oauthUrl OAuth get accesstoken request url
 * @return {'client_id', 'client_secret', 'redirect_uri', 'state', 'access_token'}
 */
const oauthGetAccesstoken = async (req:IncomingMessage, res:ServerResponse, provider:string, accesstokenUrl:string): Promise<any> => {
  //console.log(`[vtecxnext oauthGetAccesstoken] start. provider=${provider} oauthUrl=${accesstokenUrl}`)

  // stateチェック
  const parseUrl = urlmodule.parse(req.url ?? '', true)
  const state = parseUrl.query.state
  const code = parseUrl.query.code
  if (!state) {
    throw new VtecxNextError(401, `Could not get state on redirect.`)
  }
  if (!code) {
    throw new VtecxNextError(401, `Could not get code on redirect.`)
  }

  // vte.cxへリクエスト (stateチェック)
  const vtecxMethod = 'POST'
  const vtecxUrl = `${SERVLETPATH_OAUTH}/${provider}/check_state?state=${state}`
  //console.log(`[vtecxnext oauthGetAccesstoken] vtecxUrl=${vtecxUrl}`)
  let vtecxResponse:Response
  try {
    vtecxResponse = await requestVtecx(vtecxMethod, vtecxUrl, req)
  } catch (e) {
    throw newFetchError(e, true)
  }
  //console.log(`[vtecxnext oauthGetAccesstoken] check_state response status=${vtecxResponse.status}`)
  // vte.cxからのset-cookieを転記
  setCookie(vtecxResponse, res)
  // レスポンスのエラーチェック
  await checkVtecxResponse(vtecxResponse)
  // 戻り値
  const data = await getJson(vtecxResponse)
  // stateチェック
  if (!data || !data.feed || !data.feed.title) {
    throw new VtecxNextError(401, `Invalid state.`)
  }
  const client_id = data.feed.subtitle
  const client_secret = data.feed.rights
  const redirect_uri = data.feed.link[0].___href
  //console.log(`[vtecxnext oauthGetAccesstoken] client_id=${client_id}`)
  //console.log(`[vtecxnext oauthGetAccesstoken] client_secret=${client_secret}`)
  //console.log(`[vtecxnext oauthGetAccesstoken] redirect_uri=${redirect_uri}`)
  const encodeRedirect_uri = encodeURIComponent(redirect_uri)
  //console.log(`[vtecxnext oauthGetAccesstoken] encode redirect_uri=${encodeRedirect_uri}`)

  // アクセストークン取得URL生成
  const accesstokenMethod = 'POST'
  const accessTokenData = {
    'grant_type': 'authorization_code',
    'code': code,
    'redirect_uri': redirect_uri,
    'client_id': client_id,
    'client_secret': client_secret
  }
  const accesstokenBody = createURLSearchParams(accessTokenData);

  //const accesstokenBodyStr = `grant_type=authorization_code&code=${code}&redirect_uri=${encodeRedirect_uri}&client_id=${client_id}&client_secret=${client_secret}`
  //console.log(`[vtecxnext oauthGetAccesstoken] accesstokenUrl=${accesstokenUrl}`)
  //console.log(`[vtecxnext oauthGetAccesstoken] accesstokenBodyStr=${accesstokenBodyStr}`)
  //const accesstokenBody = Buffer.from(accesstokenBodyStr, 'utf-8')
  const requestInit:RequestInit = {
    body: accesstokenBody,
    method: accesstokenMethod
  }

  let accesstokenResponse:Response
  try {
    accesstokenResponse = await fetchProc(accesstokenUrl, requestInit)
  } catch (e) {
    throw newFetchError(e, false)
  }
  if (accesstokenResponse.status !== 200) {
    const errorInfo = await accesstokenResponse.json()
    //console.log(`[vtecxnext oauthGetAccesstoken] Get accesstoken failed. ${JSON.stringify(errorInfo)}`)
    const errMsg = `${'error' in errorInfo ? errorInfo.error + '. ' : ''} ${'error_description' in errorInfo ? errorInfo.error_description : ''}`
    throw new VtecxNextError(401, `Get accesstoken failed. status=${accesstokenResponse.status} ${errMsg}`)
  }
  const accesstokenInfo = await accesstokenResponse.json()
  const access_token = accesstokenInfo.access_token
  if (!access_token) {
    throw new VtecxNextError(401, `Get accesstoken failed.`)
  }

  return {
    'client_id' : client_id, 
    'client_secret' : client_secret, 
    'redirect_uri' : redirect_uri, 
    'state' : state, 
    'access_token' : access_token
  }
}

/**
 * OAuth get userinfo request
 * @param req request (for authentication)
 * @param res response (for authentication)
 * @param oauthInfo OAuth info {'client_id', 'client_secret', 'redirect_uri', 'state', 'access_token'}
 * @return userinfo {'guid', 'nickname', 'state'}
 */
const oauthGetUserinfoLine = async (req:IncomingMessage, res:ServerResponse, oauthInfo:any): Promise<any> => {
  //console.log(`[vtecxnext oauthGetUserinfoLine] start. oauthInfo=${JSON.stringify(oauthInfo)}`)

  // LINEユーザ識別情報取得リクエスト
  const url = 'https://api.line.me/v2/profile'
  const method = 'GET'
  const headers = {'Authorization' : `Bearer ${oauthInfo.access_token}`}
  //console.log(`[vtecxnext oauthGetUserinfoLine] url=${url}`)
  const requestInit:RequestInit = {
    headers: headers,
    method: method
  }
  let response:Response
  try {
    response = await fetchProc(url, requestInit)
  } catch (e) {
    throw newFetchError(e, false)
  }

  if (response.status !== 200) {
    throw new VtecxNextError(401, `Get user information failed. status=${response.status}`)
  }
  const userInfo = await response.json()
  const guid = 'userId' in userInfo ? userInfo.userId : undefined
  const nickname = 'displayName' in userInfo ? userInfo.displayName : ''
  if (!guid) {
    throw new VtecxNextError(401, `Get user information failed. `)
  }
  return {
    'guid' : guid, 
    'nickname' : nickname, 
    'state' : oauthInfo.state
  }
}

/**
 * OAuth user link.
 * @param req request
 * @param res response
 * @param provider OAuth provider name
 * @param userInfo user info
 * @return true if log in has been successful.
 */
const oauthLink = async (req:IncomingMessage, res:ServerResponse, provider:string, userInfo:any): Promise<boolean> => {
  //console.log(`[vtecxnext oauthLink] start. userInfo=${JSON.stringify(userInfo)}`)
  // OAuthリンク・ログイン
  // reCAPTCHA tokenは任意
  //const param = reCaptchaToken ? `&g-recaptcha-token=${reCaptchaToken}` : ''
  const param = ''
  const method = 'POST'
  const url = `${SERVLETPATH_OAUTH}/${provider}/link?state=${userInfo.state}${param}`
  const reqFeed = [{'title' : userInfo.guid, 'subtitle' : userInfo.nickname}]
  let response:Response
  try {
    response = await fetchVtecx(method, url, {}, JSON.stringify(reqFeed))
  } catch (e) {
    throw newFetchError(e, true)
  }
  const feed = await response.json()
  // vte.cxからのset-cookieを転記
  setCookie(response, res)
  // レスポンスのエラーチェック
  let isLoggedin
  if (response.status < 400) {
    isLoggedin = true
  } else {
    isLoggedin = false
  }
  //console.log(`[vtecxnext oauthLink] end. status=${response.status} message=${feed.feed.title}`)
  return isLoggedin
}

/**
 * URLからOriginを取得
 * @param oauthUrl URL
 * @returns Origin
 */
const getOrigin = (oauthUrl:string):string => {
  const tmpIdx = oauthUrl.indexOf('://') + 3
  let idx = oauthUrl.indexOf('/', tmpIdx)
  if (idx < 0) {
    idx = oauthUrl.length
  }
  return oauthUrl.substring(0, idx)
}

/**
 * URLSearchParamsを生成.
 * @param data JSON
 * @returns URLSearchParams
 */
const createURLSearchParams = (data:any) => {
  const params = new URLSearchParams()
  Object.keys(data).forEach(key => params.append(key, data[key]))
  return params
}
