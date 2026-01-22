import { NextRequest } from 'next/server'
import { cookies } from 'next/headers'
import SqlString from 'sqlstring'
import type { Readable } from 'node:stream'

/**
 * Hello world.
 */
export const hello = (): void => {
  console.log('[vtecxnext] Hello vtecxnext.')
}

/** vte.cx URL */
const VTECX_URL = process.env.VTECX_URL ?? ''
const VTECX_SERVICENAME = process.env.VTECX_SERVICENAME ?? ''
/** vte.cx servlet path */
const SERVLETPATH_DATA = '/d'
const SERVLETPATH_PROVIDER = '/p'
const SERVLETPATH_OAUTH = '/o'
/** header : nextpage */
const HEADER_NEXTPAGE = 'x-vtecx-nextpage'
/** The number of cursors to create (for practical paging) */
const PAGINATION_NUM = 7
/** pagination memorysort */
const MEMORYSORT = 'memorysort'
/** parameter : nextpage */
const PARAM_NEXTPAGE = 'p'

/** Request feed */
export interface LegacyFeed {
  feed: Feed
}

/** Message response */
export interface MessageResponse {
  feed: Feed
}

/** Feed */
export interface Feed {
  author?: Author[]
  category?: Category[]
  contributor?: Contributor[]
  generator?: Generator
  icon?: string
  id?: string
  link?: Link[]
  logo?: string
  rights?: string
  title?: string
  subtitle?: string
  updated?: string
  entry?: Entry[]
}

/** Entry */
export interface Entry {
  author?: Author[]
  category?: Category[]
  content?: Content
  contributor?: Contributor[]
  id?: string
  link?: Link[]
  published?: string
  rights?: string
  summary?: string
  title?: string
  subtitle?: string
  updated?: string
}

/** Author */
export interface Author {
  name?: string
  uri?: string
  email?: string
}

/** Category */
export interface Category {
  ___term?: string
  ___scheme?: string
  ___label?: string
}

/** Content */
export interface Content {
  ______text: string
}

/** Link */
export interface Link {
  ___href?: string
  ___rel?: string
  ___title?: string
}

/** Contributor */
export interface Contributor {
  uri?: string
  email?: string
  name?: string
}

export type StatusMessage = {
  // statud
  status: number
  // message
  message: string
}

export type AdduserInfo = {
  // user name
  username?: string
  // password
  pswd?: string
  // nickname
  nickname?: string
  // email subject
  emailSubject?: string
  // email text message
  emailText?: string
  // email html message
  emailHtml?: string
}

export type ChangepassByAdminInfo = {
  // uid
  uid: string
  // password
  pswd: string
}

export type CreateGroupadminInfo = {
  // group name
  group: string
  // uid list
  uids: string[]
}

export type PaginationInfo = {
  // last page number
  lastPageNumber: number
  // count with range
  countWithinRange: number
  // true if it has next page
  hasNext: boolean
  // true if it has sorted in memory
  isMemorysort: boolean
}

export type ContentSignedUrl = {
  // url
  url: string
  // key
  key: string
}

export interface OAuthInfo {
  client_id?: string
  client_secret?: string
  redirect_uri?: string
  state?: string|string[]
  access_token?: string
}

export interface OAuthUserInfo {
  guid?: string
  nickname?: string
  state?: string|string[]
}

/**
 * vtecxnext.
 * Executes various operations for the vte.cx service.
 * 
 * The following environment variables must be defined.
 * 
 *  - VTECX_URL: URL of the vte.cx service
 *  - VTECX_APIKEY: API key
 * 
 * When connecting to other vte.cx services, define the following environment variables.
 * 
 *  - SERVICEKEY_{service name}: Service key of the target service
 * 
 */
export class VtecxNext {
  /** Request (for api) */
  readonly req: NextRequest | undefined
  /** Response status */
  private resStatus: number = 200
  /** Response headers */
  private resHeaders: any = {}
  /** binary data */
  private bufferData: ArrayBuffer | null = null
  /** Access Token (for batch) */
  private accessToken: string | undefined
  /** login cookies */
  private loginCookies: any = {}
  /** next cookies (for server action) */
  private cookieStore: any  // ReadonlyRequestCookies
  /** flag whether the next cookies should be created */
  private shouldBeCreatedCookieStore: boolean = true

  /**
   * constructor
   * @param req Request (for api)
   * @param accessToken Access token (for batch)
   */
  constructor(req?: NextRequest, accessToken?: string) {
    if (req) {
      this.req = req
      this.shouldBeCreatedCookieStore = false
    } else {
      this.req = undefined
      this.accessToken = accessToken
    }
  }

  /**
   * get url parameter.
   * @param name parameter name
   * @returns parameter value
   */
  getParameter = (name: string): string | undefined => {
    if (!this.req) {
      throw new VtecxNextError(421, 'Request is required.')
    }
    const url = new URL(this.req.url)
    const params = url.searchParams
    const val = params.get(name)
    if (val === null) {
      return undefined
    }
    return val
  }

  /**
   * Check if URL parameters exist.
   * @param name パラメータ名
   * @return URLパラメータがある場合true
   */
  hasParameter = (name: string): boolean => {
    const tmpVal = this.getParameter(name)
    //console.log(`[hasParameter] ${name}=${tmpVal}`)
    return tmpVal === undefined || tmpVal === null ? false : true
  }

  /**
   * get binary data from stream
   * @param readable if undefined, return the request buffer.
   * @returns buffer
   */
  buffer = async (readable?: Readable): Promise<Uint8Array> => {
    if (!this.req) {
      throw new VtecxNextError(421, 'Request is required.')
    }
    let tmpReadable: Readable
    if (readable === undefined || readable === null) {
      const arrayBuffer = await this.req.arrayBuffer()
      return new Uint8Array(arrayBuffer)
    } else {
      tmpReadable = readable
    }
    return await buffer(tmpReadable)
  }

  /**
   * null、undefined、空文字の判定
   * @param val チェック値
   * @returns null、undefined、空文字の場合true
   */
  isBlank = (val: any): boolean => {
    return isBlank(val)
  }

  /**
   * undefined、nullを空文字に変換
   * @param val 文字列
   * @returns 変換した文字列
   */
  null2blank = (val: string | undefined | null): string => {
    if (val == undefined || val == null) {
      return ''
    }
    return val
  }

  /**
   * X-Requested-With header check.
   * If not specified, set status 401 to the response.
   * @return Response if no X-Requested-With header is specified
   */
  checkXRequestedWith = (): Response | undefined => {
    //console.log(`[vtecxnext checkXRequestedWith] start.`)
    if (!this.req) {
      throw new VtecxNextError(421, 'Request is required.')
    }
    let hasX: boolean = false
    this.req.headers.forEach((value, key, parent) => {
      //console.log(`[vtecxnext checkXRequestedWith] key=${key} value=${value}`)
      if (!hasX) {
        const keyLower = key.toLocaleLowerCase()
        if (
          (keyLower.startsWith('x-') && !keyLower.startsWith('x-forwarded')) ||
          keyLower === 'authorization'
        ) {
          //console.log(`[vtecxnext checkXRequestedWith] key=${key} value=${value}`)
          hasX = true
        }
      }
    })
    //console.log(`[vtecxnext checkXRequestedWith] end.`)

    if (!hasX) {
      return new Response('', {
        status: 401
      })
    }
  }

  /**
   * set response header
   * @param name name
   * @param value value
   */
  setResponseHeader = (name: string, value: string): void => {
    this.resHeaders[name] = value
  }

  /**
   * response
   * @param status response status code
   * @param data response data
   * @returns Response object
   */
  response = (status?: number, data?: any): Response => {
    if (status) {
      this.resStatus = status
    }
    let resData = null
    if (this.resStatus !== 204) {
      if (data) {
        if (data instanceof Object) {
          if (!('content-type' in this.resHeaders) && !('Content-Type' in this.resHeaders)) {
            this.resHeaders['content-type'] = 'application/json'
          }
          resData = JSON.stringify(data)
        } else {
          resData = data
        }
      } else if (this.bufferData) {
        resData = this.bufferData
      } else {
        resData = ''
      }
    }
    //console.log(`[vtecxnext response] resHeaders = ${JSON.stringify(this.resHeaders)}`)
    return new Response(resData, {
      status: this.resStatus,
      headers: this.resHeaders
    })
  }

  /**
   * Sends an feed response(including message) to the client using the specified status.
   * @param statusCode status code
   * @param message message
   * @return true
   */
  sendMessage = (statusCode: number, message: string): Response => {
    const resJson:MessageResponse = { feed: { title: message } }
    return this.response(statusCode, resJson)
  }

  /**
   * whether you are logged in
   * @return true if logged in
   */
  isLoggedin = async (): Promise<boolean> => {
    //console.log('[vtecxnext isLoggedin] start.')
    try {
      await this.uid()
      return true
    } catch (error) {
      return false
    }
  }

  /**
   * get current datetime
   * @return current datetime
   */
  now = async (): Promise<string> => {
    //console.log('[vtecxnext now] start.')
    // vte.cxへリクエスト
    const method = 'GET'
    const url = '/d/?_now'
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
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
   * @return uid
   */
  uid = async (): Promise<string> => {
    //console.log('[vtecxnext uid] start.')
    // vte.cxへリクエスト
    const method = 'GET'
    const url = '/d/?_uid'
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext uid] response=${response}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    const data = await getJson(response)
    return data.feed.title
  }

  /**
   * get login account
   * @return account
   */
  account = async (): Promise<string> => {
    //console.log('[vtecxnext account] start.')
    // vte.cxへリクエスト
    const method = 'GET'
    const url = '/d/?_account'
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext account] response=${response}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    const data = await getJson(response)
    //console.log(`[vtecxnext account] data = ${JSON.stringify(data)}`)
    return data.feed.title
  }

  /**
   * get login service
   * @return service
   */
  service = async (): Promise<string> => {
    //console.log('[vtecxnext service] start.')
    // vte.cxへリクエスト
    const method = 'GET'
    const url = '/d/?_service'
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext service] response=${response}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    const data = await getJson(response)
    return data.feed.title
  }

  /**
   * get RXID
   * @return RXID
   */
  rxid = async (): Promise<string> => {
    //console.log('[vtecxnext rxid] start.')
    // vte.cxへリクエスト
    const method = 'GET'
    const url = '/d/?_getrxid'
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext rxid] response=${response}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    const data = await getJson(response)
    return data.feed.title
  }

  /**
   * login.
   * Request authentication with WSSE.
   * If the login is successful, sets the authentication information in a cookie.
   * @param wsse WSSE
   * @param reCaptchaToken reCAPTCHA token
   * @return status and message
   */
  login = async (wsse: string, reCaptchaToken?: string): Promise<StatusMessage> => {
    //console.log('[vtecxnext login] start.')
    // 入力チェック
    checkNotNull(wsse, 'Authentication information')
    // ログイン
    // reCAPTCHA tokenは任意
    const param = reCaptchaToken ? `&g-recaptcha-token=${reCaptchaToken}` : ''
    const method = 'GET'
    const url = `${SERVLETPATH_DATA}/?_login${param}`
    const headers = { 'X-WSSE': `${wsse}` }
    let response: Response
    try {
      response = await this.requestVtecx(method, url, null, headers)
    } catch (e) {
      throw newFetchError(e, true)
    }
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // 引き続きAPIで処理を行う場合のため、set-cookie情報を保持しておく
    this.setLoginCookie(response)
    const data = await response.json()
    return { status: response.status, message: data.feed.title }
  }

  /**
   * login with RXID.
   * If the login is successful, sets the authentication information in a cookie.
   * @param rxid RXID
   * @return status and message
   */
  loginWithRxid = async (rxid: string): Promise<StatusMessage> => {
    //console.log('[vtecxnext loginWithRxid] start.')
    // 入力チェック
    checkNotNull(rxid, 'Authentication information')
    // ログイン
    // reCAPTCHA tokenは任意
    const method = 'GET'
    const url = `${SERVLETPATH_DATA}/?_login&_RXID=${rxid}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // 引き続きAPIで処理を行う場合のため、set-cookie情報を保持しておく
    this.setLoginCookie(response)
    const data = await response.json()
    return { status: response.status, message: data.feed.title }
  }

  /**
   * login with Time-based One Time Password.
   * If the login is successful, sets the authentication information in a cookie.
   * @param totp Time-based One Time Password
   * @param isTrustedDevice true if trusted device
   * @return status and message
   */
  loginWithTotp = async (totp: string, isTrustedDevice: boolean): Promise<StatusMessage> => {
    //console.log('[vtecxnext loginWithTotp] start.')
    // 入力チェック
    checkNotNull(totp, 'Authentication information')
    // ログイン
    const method = 'GET'
    const url = `${SERVLETPATH_DATA}/?_login`
    const headers: any = { Authorization: `TOTP ${totp}` }
    if (isTrustedDevice) {
      headers['X-TRUSTED-DEVICE'] = 'true'
    }
    //console.log(`[vtecxnext loginWithTotp] headers = ${JSON.stringify(headers)}`)
    let response: Response
    try {
      response = await this.requestVtecx(method, url, null, headers)
    } catch (e) {
      throw newFetchError(e, true)
    }
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // 引き続きAPIで処理を行う場合のため、set-cookie情報を保持しておく
    this.setLoginCookie(response)
    const data = await response.json()
    return { status: response.status, message: data.feed.title }
  }

  /**
   * logout.
   * If the logout is successful, delete the authentication information in a cookie.
   * @return status and message
   */
  logout = async (): Promise<StatusMessage> => {
    //console.log('[vtecxnext logout] start.')
    // vte.cxへリクエスト
    const method = 'GET'
    const url = '/d/?_logout'
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext logout] response=${response}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    //console.log(`[vtecxnext logout] checkVtecxResponse ok.`)
    // 戻り値
    const data = await getJson(response)
    //console.log(`[vtecxnext logout] response message : ${data.feed.title}`)
    //return true
    return { status: response.status, message: data.feed.title }
  }

  /**
   * get login whoami
   * @return login user information
   */
  whoami = async (): Promise<Entry[]> => {
    //console.log('[vtecxnext whoami] start.')
    // vte.cxへリクエスト
    const method = 'GET'
    const url = '/d/?_whoami'
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext whoami] response=${response}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    return await getJson(response)
  }

  /**
   * register a log entry
   * @param message message
   * @param title title
   * @param subtitle subtitle
   * @return true if successful
   */
  log = async (message: string, title?: string, subtitle?: string): Promise<boolean> => {
    const logTitle = title ?? 'JavaScript'
    const logSubtitle = subtitle ?? 'INFO'
    const feed = [{ title: logTitle, subtitle: logSubtitle, summary: message }]

    const method = 'POST'
    const url = `${SERVLETPATH_PROVIDER}/?_log`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(feed))
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext log] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 正常処理
    return true
  }

  /**
   * get entry
   * @param uri key
   * @param targetService target service name (for service linkage)
   * @return entry
   */
  getEntry = async (uri: string, targetService?: string): Promise<Entry|undefined> => {
    //console.log('[vtecxnext getEntry] start.')
    // キー入力値チェック
    checkUri(uri)
    // vte.cxへリクエスト
    const method = 'GET'
    const url = `${SERVLETPATH_PROVIDER}${uri}?e`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, null, null, targetService)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext getEntry] response=${response}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    return await getJson(response)
  }

  /**
   * get feed
   * @param uri key and conditions
   * @param targetService target service name (for service linkage)
   * @return feed (entry array)
   */
  getFeed = async (uri: string, targetService?: string): Promise<Entry[]|undefined> => {
    //console.log('[vtecxnext getFeed] start.')
    const vtecxRes: VtecxResponse<Entry[]|undefined> = await this.getFeedResponse(uri, targetService)
    return vtecxRes.data
  }

  /**
   * get feed
   * @param uri key and conditions
   * @param targetService target service name (for service linkage)
   * @return feed (entry array). Returns a cursor in the header if more data is available. (x-vtecx-nextpage)
   */
  getFeedResponse = async (uri: string, targetService?: string): Promise<VtecxResponse<Entry[]|undefined>> => {
    //console.log('[vtecxnext getFeedResponse] start.')
    // キー入力値チェック
    checkUri(uri)
    // vte.cxへリクエスト
    const method = 'GET'
    const url = `${SERVLETPATH_PROVIDER}${uri}${uri.includes('?') ? '&' : '?'}f`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, null, null, targetService)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext getFeed] response=${response}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    const data: any = await getJson(response)
    let header: any = undefined
    const nextpage = response.headers.get(HEADER_NEXTPAGE)
    if (nextpage) {
      header = {}
      header[HEADER_NEXTPAGE] = nextpage
    }
    return vtecxResponse<Entry[]>(response.status, header, data)
  }

  /**
   * get count
   * @param uri key and conditions
   * @param targetService target service name (for service linkage)
   * @return count
   */
  count = async (uri: string, targetService?: string): Promise<number | null> => {
    //console.log(`[vtecxnext count] start. uri=${uri}`)
    let cnt:number = 0
    let noRepeat:boolean = false
    let nextpage:string = ''
    const params = getParamMap(uri)
    if (params[PARAM_NEXTPAGE]) {
      noRepeat = true
    }
    do {
      const editedUri = noRepeat ? uri : addNextpage(uri, nextpage)
      //console.log(`[vtecxnext count] editedUri=${editedUri}`)
      nextpage = ''
      const vtecxRes: VtecxResponse<MessageResponse> = 
        await this.countResponse(editedUri, targetService)
      if (vtecxRes.status === 200) {
        const data = vtecxRes.data
        if (!data?.feed?.title) {
          if (!cnt) {
            return null
          }
        } else {
          cnt += Number(data.feed.title)
        }
        if (vtecxRes.header?.hasOwnProperty(HEADER_NEXTPAGE)) {
          nextpage = vtecxRes.header[HEADER_NEXTPAGE]
          //console.log(`[vtecxnext count] ${HEADER_NEXTPAGE}=${nextpage}`)
        }
      }
    } while (!noRepeat && nextpage)
    return cnt
  }

  /**
   * get count
   * @param uri key and conditions
   * @param targetService target service name (for service linkage)
   * @return feed. Returns a cursor in the header if more data is available. (x-vtecx-nextpage)
   */
  countResponse = async (uri: string, targetService?: string): Promise<VtecxResponse<MessageResponse>> => {
    //console.log('[vtecxnext countResponse] start.')
    // キー入力値チェック
    checkUri(uri)
    // vte.cxへリクエスト
    const method = 'GET'
    const url = `${SERVLETPATH_PROVIDER}${uri}${uri.includes('?') ? '&' : '?'}c`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, null, null, targetService)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext count] response=${response}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    const data: MessageResponse = await getJson(response)
    let header: any = undefined
    const nextpage = response.headers.get(HEADER_NEXTPAGE)
    if (nextpage) {
      header = {}
      header[HEADER_NEXTPAGE] = nextpage
    }
    return vtecxResponse(response.status, header, data)
  }

  /**
   * register entries
   * @param feed entries (JSON)
   * @param uri parent key if not specified in entry
   * @param targetService target service name (for service linkage)
   * @return registed entries
   */
  post = async (feed: Entry[], uri?: string, targetService?: string): Promise<Entry[]|MessageResponse> => {
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
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(feed), null, targetService)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext post] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return await getJson(response)
  }

  /**
   * update entries
   * @param feed entries (JSON)
   * @param isbulk Forcibly execute even if it exceeds the upper limit of entries of request feed.
   * @param parallel Execute parallel if this param is true. Valid only if 'isbulk' is true.
   * @param async Execute asynchronous if this param is true. Valid only if 'isbulk' is true.
   * @param targetService target service name (for service linkage)
   * @return updated entries
   */
  put = async (
    feed: Entry[],
    isbulk?: boolean,
    parallel?: boolean,
    async?: boolean,
    targetService?: string
  ): Promise<Entry[]|MessageResponse> => {
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
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(feed), null, targetService)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext put] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return await getJson(response)
  }

  /**
   * delete entry
   * @param uri key
   * @param revision number of revision
   * @param targetService target service name (for service linkage)
   * @return true if successful
   */
  deleteEntry = async (
    uri: string,
    revision?: number,
    targetService?: string
  ): Promise<boolean> => {
    //console.log(`[vtecxnext deleteEntry] start. uri=${uri} revision=${revision}`)
    // キー入力値チェック
    checkUri(uri)
    // vte.cxへリクエスト
    const method = 'DELETE'
    const param = revision ? `&r=${revision}` : ''
    const url = `${SERVLETPATH_PROVIDER}${uri}?e${param}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, null, null, targetService)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext deleteEntry] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return true
  }

  /**
   * delete entries
   * @param feed feed
   * @param isbulk Forcibly execute even if it exceeds the upper limit of entries of request feed.
   * @param parallel Execute parallel if this param is true. Valid only if 'isbulk' is true.
   * @param async Execute asynchronous if this param is true. Valid only if 'isbulk' is true.
   * @param targetService target service name (for service linkage)
   * @return true if successful
   */
  deleteEntries = async (
    feed: Entry[],
    isbulk?: boolean,
    parallel?: boolean,
    async?: boolean,
    targetService?: string
  ): Promise<boolean> => {
    //console.log(`[vtecxnext deleteEntries] start.`)
    // 入力チェック
    checkNotNull(feed, 'Feed')
    // キー入力値チェック
    for (const entry of feed) {
      if (!entry.link || !Array.isArray(entry.link)) {
        throw new VtecxNextError(400, `Key is required.`)
      }
      let existKey:boolean = false
      for (const link of entry.link) {
        if (link.___rel === 'self') {
          checkUri(link.___href)
          existKey = true
        }
      }
      if (!existKey) {
        throw new VtecxNextError(400, `Key is required.`)
      }
    }
    // IDに削除オプションを追加
    const paramDelete = '?_delete'
    const paramDelete2 = '&_delete'
    const reqFeed:Entry[] = [...feed]
    for (const entry of reqFeed) {
      let id:string
      if (!entry.id) {
        id = paramDelete
      } else if (entry.id.indexOf(paramDelete) >= 0 ||
          entry.id.indexOf(paramDelete2) >= 0) {
        id = entry.id
      } else {
        if (entry.id.indexOf('?') >= 0) {
          id = `${entry.id}${paramDelete2}`
        } else {
          id = `${entry.id}${paramDelete}`
        }
      }
      entry.id = id
    }

    //console.log(`[vtecxnext deleteEntries] reqFeed = ${JSON.stringify(reqFeed)}`)

    // vte.cxへリクエスト
    const method = 'PUT'
    let additionalParam = ''
    if (isbulk) {
      additionalParam = (parallel ? '&_bulk' : '&_bulkserial') + (async ? '&_async' : '')
    }
    const url = `${SERVLETPATH_PROVIDER}/?e${additionalParam}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(reqFeed), null, targetService)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext deleteEntries] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return true
  }

  /**
   * delete folder
   * @param uri parent key
   * @param async execute async
   * @param targetService target service name (for service linkage)
   * @return true if successful
   */
  deleteFolder = async (uri: string, async?: boolean, targetService?: string): Promise<boolean> => {
    //console.log(`[vtecxnext deleteFolder] start. uri=${uri} async=${async}`)
    // キー入力値チェック
    checkUri(uri)
    // vte.cxへリクエスト
    const method = 'DELETE'
    const url = `${SERVLETPATH_PROVIDER}${uri}?_rf${async ? '&_async' : ''}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, null, null, targetService)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext deleteFolder] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return true
  }

  /**
   * clear folder
   * @param uri parent key
   * @param async execute async
   * @param targetService target service name (for service linkage)
   * @return true if successful
   */
  clearFolder = async (uri: string, async?: boolean, targetService?: string): Promise<boolean> => {
    //console.log(`[vtecxnext clearFolder] start. uri=${uri} async=${async}`)
    // キー入力値チェック
    checkUri(uri)
    // vte.cxへリクエスト
    const method = 'DELETE'
    const url = `${SERVLETPATH_PROVIDER}${uri}?_clearfolder${async ? '&_async' : ''}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, null, null, targetService)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext clearFolder] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return true
  }

  /**
   * allocate numbers
   * @param uri key
   * @param num number to allocate
   * @param targetService target service name (for service linkage)
   * @return allocated numbers. comma separated if multiple.
   */
  allocids = async (uri: string, num: number, targetService?: string): Promise<string> => {
    //console.log('[vtecxnext allocids] start.')
    // キー入力値チェック
    checkUri(uri)
    checkNotNull(num, 'number to allocate')
    // vte.cxへリクエスト
    const method = 'GET'
    const url = `${SERVLETPATH_PROVIDER}${uri}?_allocids=${num}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, null, null, targetService)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext allocids] response=${response}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    const data = await getJson(response)
    return data.feed.title
  }

  /**
   * add a number
   * @param uri key
   * @param num number to add
   * @param targetService target service name (for service linkage)
   * @return added number
   */
  addids = async (uri: string, num: number, targetService?: string): Promise<number | null> => {
    //console.log('[vtecxnext addids] start.')
    // キー入力値チェック
    checkUri(uri)
    checkNotNull(num, 'number to add')
    // vte.cxへリクエスト
    const method = 'PUT'
    const url = `${SERVLETPATH_PROVIDER}${uri}?_addids=${num}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, null, null, targetService)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext addids] response=${response}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    const data = await getJson(response)
    return data.feed.title ? Number(data.feed.title) : null
  }

  /**
   * get a added number
   * @param uri key
   * @param targetService target service name (for service linkage)
   * @return added number
   */
  getids = async (uri: string, targetService?: string): Promise<number | null> => {
    //console.log('[vtecxnext getids] start.')
    // キー入力値チェック
    checkUri(uri)
    // vte.cxへリクエスト
    const method = 'GET'
    const url = `${SERVLETPATH_PROVIDER}${uri}?_getids`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, null, null, targetService)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext getids] response=${response}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    const data = await getJson(response)
    return data.feed.title ? Number(data.feed.title) : null
  }

  /**
   * set a number
   * @param uri key
   * @param num number to set
   * @param targetService target service name (for service linkage)
   * @return set number
   */
  setids = async (uri: string, num: number, targetService?: string): Promise<number | null> => {
    //console.log('[vtecxnext setids] start.')
    // キー入力値チェック
    checkUri(uri)
    checkNotNull(num, 'number to set')
    // vte.cxへリクエスト
    const method = 'PUT'
    const url = `${SERVLETPATH_PROVIDER}${uri}?_setids=${num}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, null, null, targetService)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext setids] response=${response}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    const data = await getJson(response)
    return data.feed.title ? Number(data.feed.title) : null
  }

  /**
   * set a addition range
   * @param uri key
   * @param range addition range. delete if blank.
   * @param targetService target service name (for service linkage)
   * @return addition range
   */
  rangeids = async (uri: string, range: string): Promise<string> => {
    //console.log(`[vtecxnext rangeids] start. range=${range}`)
    // 入力値チェック
    checkUri(uri)
    //checkNotNull(range, 'range')  // 空の場合加算枠削除
    // vte.cxへリクエスト
    const method = 'PUT'
    const url = `${SERVLETPATH_PROVIDER}${uri}?_rangeids`
    const feed = { feed: { title: range } }
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(feed))
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext rangeids] response=${response}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    const data = await getJson(response)
    if (data.feed?.title) {
      return data.feed.title
    } else {
      return ''
    }
  }

  /**
   * get a addition range
   * @param uri key
   * @param targetService target service name (for service linkage)
   * @return addition range
   */
  getRangeids = async (uri: string): Promise<string|undefined> => {
    //console.log('[vtecxnext getrangeids] start.')
    // キー入力値チェック
    checkUri(uri)
    // vte.cxへリクエスト
    const method = 'GET'
    const url = `${SERVLETPATH_PROVIDER}${uri}?_rangeids`
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext getrangeids] response=${response}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    const data = await getJson(response)
    //console.log(`[vtecxnext getRangeids] status=${String(response.status)} data=${JSON.stringify(data)}`)
    return data.feed?.title
  }

  /**
   * set feed to session
   * @param name name
   * @param feed entries (JSON)
   * @return true if successful
   */
  setSessionFeed = async (name: string, feed: Entry[]): Promise<boolean> => {
    // 入力チェック
    checkNotNull(name, 'Name')
    checkNotNull(feed, 'Feed')
    // vte.cxへリクエスト
    const method = 'PUT'
    const url = `${SERVLETPATH_PROVIDER}/?_sessionfeed=${name}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(feed))
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext setSessionFeed] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return true
  }

  /**
   * set entry to session
   * @param name name
   * @param entry entry (JSON)
   * @return true if successful
   */
  setSessionEntry = async (name: string, entry: Entry): Promise<boolean> => {
    //console.log(`[vtecxnext setSessionEntry] start. name=${name} entry=${JSON.stringify(entry)}`)
    // 入力チェック
    checkNotNull(name, 'Name')
    checkNotNull(entry, 'Entry')
    // vte.cxへリクエスト
    const method = 'PUT'
    const url = `${SERVLETPATH_PROVIDER}/?_sessionentry=${name}`
    const feed = { feed: { entry: [ entry ] } }
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(feed))
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext setSessionEntry] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return true
  }

  /**
   * set string to session
   * @param name name
   * @param str string
   * @return true if successful
   */
  setSessionString = async (name: string, str: string): Promise<boolean> => {
    //console.log(`[vtecxnext setSessionString] start. name=${name} str=${str}`)
    // 入力チェック
    checkNotNull(name, 'Name')
    checkNotNull(str, 'String')
    // vte.cxへリクエスト
    const method = 'PUT'
    const url = `${SERVLETPATH_PROVIDER}/?_sessionstring=${name}`
    const feed = { feed: { title: str } }
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(feed))
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext setSessionString] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return true
  }

  /**
   * set number to session
   * @param name name
   * @param num number
   * @return true if successful
   */
  setSessionLong = async (name: string, num: number): Promise<boolean> => {
    //console.log(`[vtecxnext setSessionLong] start. name=${name} num=${num}`)
    // 入力チェック
    checkNotNull(name, 'Name')
    checkNotNull(num, 'Number')
    // vte.cxへリクエスト
    const method = 'PUT'
    const url = `${SERVLETPATH_PROVIDER}/?_sessionlong=${name}`
    const feed = { feed: { title: String(num) } }
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(feed))
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext setSessionLong] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return true
  }

  /**
   * add number in session
   * @param name name
   * @param num number to add
   * @return true if successful
   */
  incrementSession = async (name: string, num: number): Promise<number | null> => {
    //console.log(`[vtecxnext incrementSession] start. name=${name} num=${num}`)
    // 入力チェック
    checkNotNull(name, 'Name')
    checkNotNull(num, 'Number')
    // vte.cxへリクエスト
    const method = 'PUT'
    const url = `${SERVLETPATH_PROVIDER}/?_sessionincr=${name}&_num=${num}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext incrementSession] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    const data = await getJson(response)
    return data.feed.title ? Number(data.feed.title) : null
  }

  /**
   * delete feed from session
   * @param name name
   * @return true if successful
   */
  deleteSessionFeed = async (name: string): Promise<boolean> => {
    //console.log(`[vtecxnext deleteSessionFeed] start. name=${name}`)
    // 入力チェック
    checkNotNull(name, 'Name')
    // vte.cxへリクエスト
    const method = 'DELETE'
    const url = `${SERVLETPATH_PROVIDER}/?_sessionfeed=${name}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext deleteSessionFeed] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return true
  }

  /**
   * delete entry from session
   * @param name name
   * @return true if successful
   */
  deleteSessionEntry = async (name: string): Promise<boolean> => {
    //console.log(`[vtecxnext deleteSessionEntry] start. name=${name}`)
    // 入力チェック
    checkNotNull(name, 'Name')
    // vte.cxへリクエスト
    const method = 'DELETE'
    const url = `${SERVLETPATH_PROVIDER}/?_sessionentry=${name}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext deleteSessionEntry] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return true
  }

  /**
   * delete string from session
   * @param name name
   * @return true if successful
   */
  deleteSessionString = async (name: string): Promise<boolean> => {
    //console.log(`[vtecxnext deleteSessionString] start. name=${name}`)
    // 入力チェック
    checkNotNull(name, 'Name')
    // vte.cxへリクエスト
    const method = 'DELETE'
    const url = `${SERVLETPATH_PROVIDER}/?_sessionstring=${name}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext deleteSessionString] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return true
  }

  /**
   * delete number from session
   * @param name name
   * @return true if successful
   */
  deleteSessionLong = async (name: string): Promise<boolean> => {
    //console.log(`[vtecxnext deleteSessionLong] start. name=${name}`)
    // 入力チェック
    checkNotNull(name, 'Name')
    // vte.cxへリクエスト
    const method = 'DELETE'
    const url = `${SERVLETPATH_PROVIDER}/?_sessionlong=${name}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext deleteSessionLong] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return true
  }

  /**
   * get feed from session
   * @param name name
   * @return feed
   */
  getSessionFeed = async (name: string): Promise<Entry[]|undefined> => {
    //console.log(`[vtecxnext getSessionFeed] start. name=${name}`)
    // 入力チェック
    checkNotNull(name, 'Name')
    // vte.cxへリクエスト
    const method = 'GET'
    const url = `${SERVLETPATH_PROVIDER}/?_sessionfeed=${name}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext getSessionFeed] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    return await getJson(response)
  }

  /**
   * get entry from session
   * @param name name
   * @return entry
   */
  getSessionEntry = async (name: string): Promise<Entry|undefined> => {
    //console.log(`[vtecxnext getSessionEntry] start. name=${name}`)
    // 入力チェック
    checkNotNull(name, 'Name')
    // vte.cxへリクエスト
    const method = 'GET'
    const url = `${SERVLETPATH_PROVIDER}/?_sessionentry=${name}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext getSessionEntry] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    return await getJson(response)
  }

  /**
   * get string from session
   * @param name name
   * @return string
   */
  getSessionString = async (name: string): Promise<string | null> => {
    //console.log(`[vtecxnext getSessionString] start. name=${name}`)
    // 入力チェック
    checkNotNull(name, 'Name')
    // vte.cxへリクエスト
    const method = 'GET'
    const url = `${SERVLETPATH_PROVIDER}/?_sessionstring=${name}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext getSessionString] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
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
   * @param name name
   * @return number
   */
  getSessionLong = async (name: string): Promise<number | null> => {
    //console.log(`[vtecxnext getSessionLong] start. name=${name}`)
    // 入力チェック
    checkNotNull(name, 'Name')
    // vte.cxへリクエスト
    const method = 'GET'
    const url = `${SERVLETPATH_PROVIDER}/?_sessionlong=${name}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext getSessionLong] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
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
   * @param uri key and conditions
   * @param pagerange page range
   * @param targetService target service name (for service linkage)
   * @return Maximum number of pages in the specified page range, and total count.
   */
  pagination = async (
    uri: string,
    pagerange: string,
    targetService?: string
  ): Promise<PaginationInfo> => {
    //console.log('[vtecxnext pagination] start.')
    // キー入力値チェック
    checkUri(uri)
    // vte.cxへリクエスト
    const method = 'GET'
    const url = `${SERVLETPATH_PROVIDER}${uri}${uri.includes('?') ? '&' : '?'}_pagination=${pagerange}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, null, null, targetService)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext pagination] response=${response}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値編集
    const respJson = await getJson(response)
    let hasNext = false
    if (respJson.feed.link && respJson.feed.link[0]?.___rel === 'next') {
      hasNext = true
    }
    const pagenationInfo: PaginationInfo = {
      lastPageNumber: Number(respJson.feed.title),
      countWithinRange: Number(respJson.feed.subtitle),
      hasNext: hasNext,
      isMemorysort: respJson.feed.rights === MEMORYSORT
    }
    return pagenationInfo
  }

  /**
   * get page
   * @param uri key and conditions
   * @param num page number
   * @param targetService target service name (for service linkage)
   * @return feed (entry array)
   */
  getPage = async (uri: string, num: number, targetService?: string): Promise<Entry[]|undefined> => {
    //console.log(`[vtecxnext getPage] start. uri=${uri} num=${num}`)
    // 入力値チェック
    checkUri(uri)
    checkNotNull(num, 'page number')
    // vte.cxへリクエスト
    const method = 'GET'
    const url = `${SERVLETPATH_PROVIDER}${uri}${uri.includes('?') ? '&' : '?'}n=${num}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, null, null, targetService)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext getPage] response=${response}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    return await getJson(response)
  }

  /**
   * practical paging
   * If you specify page 1, a new cursor list will be created.
   * @param uri key and conditions
   * @param num page number
   * @param targetService target service name (for service linkage)
   * @return feed (entry array)
   */
  getPageWithPagination = async (
    uri: string,
    num: number,
    targetService?: string
  ): Promise<Entry[]|undefined> => {
    //console.log(`[getPageWithPagination] start. uri=${uri} num=${num} ${targetService ? 'targetService=' + targetService : ''}`)

    // ページ数が1の場合、カーソルリスト作成処理を行う
    if (num === 1) {
      //console.log(`[getPageWithPagination] pagination start. uri=${uri}`)
      const paginationInfo = await this.pagination(
        uri,
        `1,${String(PAGINATION_NUM)}`,
        targetService
      )
      // メモリソートの場合はvte.cx側で全てのカーソルリストを作成する
      if (paginationInfo.hasNext && !paginationInfo.isMemorysort) {
        // メモリソートでない場合、次のカーソルリスト作成 (非同期のまま)
        this.nextPagination(uri, PAGINATION_NUM, targetService)
      }
      if (paginationInfo.lastPageNumber === 0) {
        // データが存在しない場合終了
        return undefined
      }
    }

    // ページ取得
    //console.log(`[getPageWithPagination] getPage start. uri=${uri} num=${num}`)
    try {
      return await this.getPage(uri, num, targetService)
    } catch (error) {
      if (isVtecxNextError(error)) {
        // ステータス400で「There is no designated page. The last page: ページ数」の場合、空データを返す。
        if (error.status === 400 && error.message.startsWith('There is no designated page.')) {
          return undefined
        }
      }
      throw error
    }
  }

  /**
   * ページングのカーソルリスト作成処理
   * 続きがある場合、次のカーソルリスト作成処理を実行する
   * @param vtecxnext
   * @param uri キーとパラメータ
   * @param prevLastPage 前回の最終ページ
   * @param targetService 対象サービス
   */
  private nextPagination = async (uri: string, prevLastPage: number, targetService?: string) => {
    const firstPage = prevLastPage + 1
    const lastPage = prevLastPage + PAGINATION_NUM
    //console.log(`[vtecxnext getPageWithPagination - nextPagination] firstPage=${firstPage} lastPage=${lastPage}`)
    try {
      const paginationInfo = await this.pagination(
        uri,
        `${String(firstPage)},${String(lastPage)}`,
        targetService
      )
      if (paginationInfo.hasNext) {
        await this.nextPagination(uri, lastPage, targetService)
      }
    } catch (e) {
      // Do nothing.
      //if (isVtecxNextError(e)) {
        //console.log(`[vtecxnext getPageWithPagination - nextPagination] status=${e.status} message=${e.message}`)
      //} else {
        //console.log(`[vtecxnext getPageWithPagination - nextPagination] Error occured. ${e}`)
      //}
    }
  }

  /**
   * post data to bigquery
   * @param feed entries (JSON)
   * @param async execute async
   * @param tablenames key:entity's prop name, value:BigQuery table name
   * @return true if successful
   */
  postBQ = async (feed: Entry[], async?: boolean, tablenames?: {[key: string]: string}): Promise<boolean> => {
    //console.log(`[vtecxnext postBQ] start. async=${async} feed=${feed}`)
    // 入力チェック
    checkNotNull(feed, 'Feed')
    // リクエストデータ
    //const reqFeed = 'feed' in feed ? feed : { feed: { entry: feed } }
    const reqFeed:LegacyFeed = { feed: { entry: feed } }
    // テーブル名の指定がある場合は指定
    const tablenamesStr = editBqTableNames(tablenames)
    if (tablenamesStr) {
      reqFeed.feed['title'] = tablenamesStr
    }
    // vte.cxへリクエスト
    const method = 'POST'
    const url = `${SERVLETPATH_PROVIDER}/?_bq${async ? '&_async' : ''}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(reqFeed))
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext postBQ] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return true
  }

  /**
   * delete data from bigquery
   * @param keys delete keys
   * @param async execute async
   * @param tablenames key:entity's prop name, value:BigQuery table name
   * @return true if successful
   */
  deleteBQ = async (keys: string[], async?: boolean, tablenames?: {[key: string]: string}): Promise<boolean> => {
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
      links[idx] = { ___href: key }
      idx++
    }
    const feed: LegacyFeed = { feed: {} }
    if (tablenamesStr) {
      feed.feed['title'] = tablenamesStr
    }
    feed.feed['link'] = links
    //console.log(`[vtecxnext deleteBQ] feed=${feed}`)
    // vte.cxへリクエスト
    const method = 'DELETE'
    const url = `${SERVLETPATH_PROVIDER}/?_bq${async ? '&_async' : ''}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(feed))
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext deleteBQ] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return true
  }

  /**
   * query bigquery
   * @param sql query sql
   * @param values values of query arguments
   * @param parent parent name of result json
   * @return query results in JSON format
   */
  getBQ = async (sql: string, values?: any[], parent?: string): Promise<any> => {
    return this.execBQ(sql, values, parent)
  }

  /**
   * query bigquery
   * @param sql query sql
   * @param values values of query arguments
   * @param parent parent name of result json
   * @return query results in JSON format
   */
  execBQ = async (sql: string, values?: any[], parent?: string): Promise<any> => {
    //console.log(`[vtecxnext execBQ] start. sql=${sql} values=${values}`)
    // 入力チェック
    checkNotNull(sql, 'Query SQL')
    // 引数生成
    const feed = editSqlArgument(sql, values, parent)
    // vte.cxへリクエスト
    const method = 'PUT'
    const url = `${SERVLETPATH_PROVIDER}/?_querybq`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(feed))
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext execBQ] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    //console.log(`[vtecxnext execBQ] setCookie end.`)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    //console.log(`[vtecxnext execBQ] checkVtecxResponse end.`)
    // 戻り値
    return await response.json()
  }

  /**
   * Search BigQuery and return results in CSV format.
   * @param sql query sql
   * @param values values of query arguments
   * @param filename file name of csv
   * @param parent parent name of result json
   * @return true
   */
  getBQCsv = async (
    sql: string,
    values?: any[],
    filename?: string,
    parent?: string
  ): Promise<boolean> => {
    //console.log(`[vtecxnext getBQCsv] start. sql=${sql} values=${values}`)
    // 入力チェック
    checkNotNull(sql, 'Query SQL')
    // 引数生成
    const feed = editSqlArgument(sql, values, parent)
    // vte.cxへリクエスト
    const method = 'PUT'
    const url = `${SERVLETPATH_PROVIDER}/?_querybq&_csv${filename ? '=' + filename : ''}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(feed))
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext getBQCsv] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    //console.log(`[vtecxnext getBQCsv] setCookie end.`)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    //console.log(`[vtecxnext getBQCsv] checkVtecxResponse end.`)
    // 戻り値
    const resData = await response.blob()
    //console.log(`[vtecxnext getBQCsv] response.blob()`)
    this.setResponseHeaders(response)
    //console.log(`[vtecxnext getBQCsv] setResponseHeaders`)
    this.bufferData = await resData.arrayBuffer()
    //console.log(`[vtecxnext getBQCsv] await resData.arrayBuffer()`)
    //res.end(new Uint8Array(csvData))
    //console.log(`[vtecxnext getBQCsv] res.end(new Uint8Array(csvData))`)
    return true
  }

  /**
   * post data to bdb and bigquery
   * @param feed entries (JSON)
   * @param uri parent key if not specified in entry
   * @param tablenames key:entity's prop name, value:BigQuery table name
   * @param async execute async
   * @return registed entries
   */
  postBDBQ = async (feed: Entry[], uri?: string, tablenames?: {[key: string]: string}, async?: boolean): Promise<Entry[]|MessageResponse> => {
    //console.log(`[vtecxnext postBQ] start. async=${async} feed=${feed}`)
    // 入力チェック
    checkNotNull(feed, 'Feed')
    if (uri) {
      // 値の設定がある場合、キー入力値チェック
      checkUri(uri)
    }

    // リクエストデータ
    const reqFeed:LegacyFeed = { feed: { entry: feed } }
    // テーブル名の指定がある場合は指定
    const tablenamesStr = editBqTableNames(tablenames)
    if (tablenamesStr) {
      reqFeed.feed['title'] = tablenamesStr
    }
    // vte.cxへリクエスト
    const method = 'POST'
    const url = `${SERVLETPATH_PROVIDER}${uri ? uri : '/'}?_bdbq${async ? '&_async' : ''}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(reqFeed))
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext postBDBQ] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return await getJson(response)
  }

  /**
   * put data to bdb and post bigquery
   * @param feed entries (JSON)
   * @param uri parent key if not specified in entry
   * @param tablenames key:entity's prop name, value:BigQuery table name
   * @param async execute async
   * @param isbulk Forcibly execute even if it exceeds the upper limit of entries of request feed.
   * @return true if successful
   */
  putBDBQ = async (feed: Entry[], uri?: string, tablenames?: {[key: string]: string}, async?: boolean, isbulk?: boolean): Promise<Entry[]|MessageResponse> => {
    //console.log(`[vtecxnext putBDBQ] start. feed=${feed}`)
    // 入力チェック
    checkNotNull(feed, 'Feed')
    if (uri) {
      // 値の設定がある場合、キー入力値チェック
      checkUri(uri)
    }

    // リクエストデータ
    const reqFeed:LegacyFeed = { feed: { entry: feed } }
    // テーブル名の指定がある場合は指定
    const tablenamesStr = editBqTableNames(tablenames)
    //console.log(`[putBDBQ] tableamesStr=${tablenamesStr}`)
    if (tablenamesStr) {
      reqFeed.feed['title'] = tablenamesStr
    }
    // vte.cxへリクエスト
    const method = 'PUT'
    const url = `${SERVLETPATH_PROVIDER}${uri ? uri : '/'}?_bdbq${async ? '&_async' : ''}${isbulk ? '&_bulk' : ''}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(reqFeed))
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext putBDBQ] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return await getJson(response)
  }

  /**
   * delete data from bdb and bigquery
   * @param keys delete keys
   * @param tablenames key:entity's prop name, value:BigQuery table name
   * @param async execute async
   * @return true if successful
   */
  deleteBDBQ = async (keys: string[], tablenames?: {[key: string]: string}, async?: boolean): Promise<boolean> => {
    //console.log(`[vtecxnext deleteBDBQ] start. keys=${keys}`)
    // 入力チェック
    checkNotNull(keys, 'Key')
    // テーブル名の指定がある場合は指定
    const tablenamesStr = editBqTableNames(tablenames)
    // キーを feed.link.___href にセットする
    const links = []
    let idx = 0
    for (const key of keys) {
      //console.log(`[vtecxnext deleteBDBQ] key=${key}`)
      links[idx] = { ___href: key }
      idx++
    }
    const feed: LegacyFeed = { feed: {} }
    if (tablenamesStr) {
      feed.feed['title'] = tablenamesStr
    }
    feed.feed['link'] = links
    //console.log(`[vtecxnext deleteBDBQ] feed=${feed}`)
    // vte.cxへリクエスト
    const method = 'DELETE'
    const url = `${SERVLETPATH_PROVIDER}/?_bdbq${async ? '&_async' : ''}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(feed))
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext deleteBDBQ] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return true
  }

  /**
   * Execute a query SQL to the database and get the result.
   * @param sql query sql
   * @param values values of query arguments
   * @param parent parent name of result json
   * @return query results in JSON format
   */
  queryRDB = async (sql: string, values?: any[], parent?: string): Promise<any> => {
    //console.log(`[vtecxnext queryRDB] start. sql=${sql} values=${values}`)
    // 入力チェック
    checkNotNull(sql, 'Query SQL')
    // 引数生成
    const feed = editSqlArgument(sql, values, parent)
    // vte.cxへリクエスト
    const method = 'PUT'
    const url = `${SERVLETPATH_PROVIDER}/?_queryrdb`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(feed))
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext execBQ] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    //console.log(`[vtecxnext execBQ] setCookie end.`)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    //console.log(`[vtecxnext execBQ] checkVtecxResponse end.`)
    // 戻り値
    return await response.json()
  }

  /**
   * Search RDB and return results in CSV format.
   * @param sql query sql
   * @param values values of query arguments
   * @param filename file name of csv
   * @param parent parent name of result json
   * @return true
   */
  queryRDBCsv = async (
    sql: string,
    values?: any[],
    filename?: string,
    parent?: string
  ): Promise<boolean> => {
    //console.log(`[vtecxnext queryRDBCsv] start. sql=${sql} values=${values}`)
    // 入力チェック
    checkNotNull(sql, 'Query SQL')
    // 引数生成
    const feed = editSqlArgument(sql, values, parent)
    // vte.cxへリクエスト
    const method = 'PUT'
    const url = `${SERVLETPATH_PROVIDER}/?_queryrdb&_csv${filename ? '=' + filename : ''}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(feed))
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext queryRDBCsv] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    //console.log(`[vtecxnext queryRDBCsv] setCookie end.`)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    //console.log(`[vtecxnext queryRDBCsv] checkVtecxResponse end.`)
    // 戻り値
    const resData = await response.blob()
    //console.log(`[vtecxnext queryRDBCsv] response.blob()`)
    this.setResponseHeaders(response)
    //console.log(`[vtecxnext queryRDBCsv] setResponseHeaders`)
    this.bufferData = await resData.arrayBuffer()
    //console.log(`[vtecxnext queryRDBCsv] await resData.arrayBuffer()`)
    //res.end(new Uint8Array(csvData))
    //console.log(`[vtecxnext queryRDBCsv] res.end(new Uint8Array(csvData))`)
    return true
  }

  /**
   * Execute SQL to the database.
   * If there are multiple SQLs, they will be wrapped in a transaction.
   * @param sqls sql list
   * @param values values of query arguments
   * @param async execute async
   * @param isbulk execute with autocommit
   * @return message
   */
  execRDB = async (
    sqls: string[],
    values?: any[][],
    async?: boolean,
    isbulk?: boolean
  ): Promise<any> => {
    //console.log(`[vtecxnext execRDB] start. sql=${sql} values=${values}`)
    // 入力チェック
    checkNotNull(sqls, 'exec SQL')
    // 引数生成
    const feed = editSqlsArgument(sqls, values)
    // vte.cxへリクエスト
    const method = 'PUT'
    const url = `${SERVLETPATH_PROVIDER}/?_execrdb${async ? '&_async' : ''}${isbulk ? '&_bulk' : ''}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(feed))
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext execRDB] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    //console.log(`[vtecxnext execBQ] setCookie end.`)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    //console.log(`[vtecxnext execRDB] checkVtecxResponse end.`)
    // 戻り値
    return await response.json()
  }

  /**
   * Create PDF.
   * Writes a PDF to the response.
   * @param htmlTemplate PDF layout
   * @param filename PDF file name
   * @return true
   */
  toPdf = async (htmlTemplate: string, filename?: string): Promise<boolean> => {
    //console.log(`[vtecxnext toPdf] start. htmlTemplate=${htmlTemplate} filename=${filename}`)
    // 入力チェック
    checkNotNull(htmlTemplate, 'PDF template')
    // vte.cxへリクエスト
    const method = 'PUT'
    const url = `${SERVLETPATH_PROVIDER}/?_pdf${filename ? '=' + filename : ''}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, htmlTemplate)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext toPdf] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    //console.log(`[vtecxnext toPdf] setCookie end.`)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    //console.log(`[vtecxnext toPdf] checkVtecxResponse end.`)
    // 戻り値
    const resData = await response.blob()
    this.setResponseHeaders(response)
    this.bufferData = await resData.arrayBuffer()
    return true
  }

  /**
   * put the signature of uri and revision.
   * @param uri key
   * @param revision revision
   * @return signed entry
   */
  putSignature = async (uri: string, revision?: number): Promise<Entry> => {
    //console.log('[vtecxnext putSignature] start.')
    // キー入力値チェック
    checkUri(uri)
    // vte.cxへリクエスト
    const method = 'PUT'
    const url = `${SERVLETPATH_PROVIDER}${uri}?_signature${revision ? '&r=' + revision : ''}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext putSignature] response=${response}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    return await getJson(response)
  }

  /**
   * puts the signature of uri and revision.
   * @param feed entries
   * @return signed entries
   */
  putSignatures = async (feed: Entry[]): Promise<Entry[]> => {
    //console.log('[vtecxnext putSignatures] start.')
    // 入力チェック
    checkNotNull(feed, 'Feed')
    // vte.cxへリクエスト
    const method = 'PUT'
    const url = `${SERVLETPATH_PROVIDER}/?_signature`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(feed))
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext putSignatures] response=${response}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    return await getJson(response)
  }

  /**
   * delete the signature.
   * @param uri key
   * @param revision revision
   * @return true if successful
   */
  deleteSignature = async (uri: string, revision?: number): Promise<boolean> => {
    //console.log('[vtecxnext deleteSignature] start.')
    // キー入力値チェック
    checkUri(uri)
    // vte.cxへリクエスト
    const method = 'DELETE'
    const url = `${SERVLETPATH_PROVIDER}${uri}?_signature${revision ? '&r=' + revision : ''}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext deleteSignature] response=${response}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return true
  }

  /**
   * check the signature.
   * @param uri key
   * @return true if the signature is valid
   */
  checkSignature = async (uri: string): Promise<boolean> => {
    //console.log('[vtecxnext checkSignature] start.')
    // キー入力値チェック
    checkUri(uri)
    // vte.cxへリクエスト
    const method = 'GET'
    const url = `${SERVLETPATH_PROVIDER}${uri}?_signature`
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext checkSignature] response=${response}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return true
  }

  /**
   * Send an mail (with attachments)
   * @param entry email contents
   * @param to email addresses to
   * @param cc email addresses cc
   * @param bcc email addresses bcc
   * @param attachments keys of attachment files
   * @return true if successful
   */
  sendMail = async (
    entry: Entry,
    to: string[],
    cc?: string[],
    bcc?: string[],
    attachments?: string[]
  ): Promise<boolean> => {
    //console.log(`[vtecxnext sendMail] start. to=${to}`)
    // 入力チェック
    checkNotNull(entry, 'Entry')
    // 引数編集
    let links: Link[] = []
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
    let feed = { feed: { entry: [entry], link: links } }
    //console.log(`[vtecxnext sendMail] feed = ${JSON.stringify(feed)}`)
    // vte.cxへリクエスト
    const method = 'POST'
    const url = `${SERVLETPATH_PROVIDER}/?_sendmail`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(feed))
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext sendMail] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return true
  }

  /**
   * push notification to clients.
   * @param message message
   * @param to clients to
   * @param title title
   * @param subtitle subtitle (Expo)
   * @param imageUrl url of image (FCM)
   * @param data key value data (Expo)
   * @return true if successful
   */
  pushNotification = async (
    message: string,
    to: string[],
    title?: string,
    subtitle?: string,
    imageUrl?: string,
    data?: {[key: string]: string}
  ): Promise<boolean> => {
    //console.log(`[vtecxnext pushNotification] start. to=${to}`)
    // 入力チェック
    checkNotNull(message, 'Message')
    checkNotNull(to, 'Destination')
    // 引数編集
    const links: Link[] = []
    for (const destination of to) {
      const link = { ___rel: 'to', ___href: destination }
      links.push(link)
    }
    const categories: Category[] = []
    if (imageUrl) {
      const category = { ___scheme: 'imageurl', ___label: imageUrl }
      categories.push(category)
    }
    if (data) {
      for (const name in data) {
        const category = { ___scheme: name, ___label: data[name] }
        categories.push(category)
      }
    }
    const content = { ______text: message }
    const entry: Entry = {}
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
    const feed = {
      feed: {
        entry: [entry],
        link: links
      }
    }
    //console.log(`[vtecxnext pushNotification] feed = ${JSON.stringify(feed)}`)
    // vte.cxへリクエスト
    const method = 'POST'
    const url = `${SERVLETPATH_PROVIDER}/?_pushnotification`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(feed))
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext pushNotification] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return true
  }

  /**
   * set status of MessageQueue.
   * @param flag true if on, false if off
   * @param channel channel
   */
  setMessageQueueStatus = async (flag: boolean, channel: string): Promise<boolean> => {
    //console.log(`[vtecxnext setMessageQueueStatus] start. channel=${channel} flag=${flag}`)
    // キー入力値チェック
    checkUri(channel)
    // vte.cxへリクエスト
    const method = 'PUT'
    const url = `${SERVLETPATH_PROVIDER}${channel}?_mqstatus=${flag ? 'true' : 'false'}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext setMessageQueueStatus] response=${response}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return true
  }

  /**
   * get status of MessageQueue.
   * @param name name
   * @return feed
   */
  getMessageQueueStatus = async (channel: string): Promise<MessageResponse> => {
    //console.log(`[vtecxnext getMessageQueueStatus] start. channel=${channel}`)
    // 入力チェック
    checkUri(channel)
    // vte.cxへリクエスト
    const method = 'GET'
    const url = `${SERVLETPATH_PROVIDER}${channel}?_mqstatus`
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext getMessageQueueStatus] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    return await getJson(response)
  }

  /**
   * set MessageQueue.
   * @param feed entries (JSON)
   * @param channel channel
   * @return true if successful
   */
  setMessageQueue = async (feed: Entry[], channel: string): Promise<boolean> => {
    //console.log(`[vtecxnext setMessageQueue] start. channel=${channel} feed=${feed}`)
    // 入力チェック
    checkUri(channel)
    checkNotNull(feed, 'Feed')
    // vte.cxへリクエスト
    const method = 'POST'
    const url = `${SERVLETPATH_PROVIDER}${channel}?_mq`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(feed))
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext setMessageQueue] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return true
  }

  /**
   * get messageQueue.
   * @param name name
   * @return feed
   */
  getMessageQueue = async (channel: string): Promise<Entry[]|undefined> => {
    //console.log(`[vtecxnext getMessageQueue] start. channel=${channel}`)
    // 入力チェック
    checkUri(channel)
    // vte.cxへリクエスト
    const method = 'GET'
    const url = `${SERVLETPATH_PROVIDER}${channel}?_mq`
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext getMessageQueue] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    return await getJson(response)
  }

  /**
   * add group
   * (not yet joined)
   * @param group group
   * @param selfid hierarchical name under my group alias
   * @return feed
   */
  addGroup = async (group: string, selfid?: string): Promise<Entry> => {
    //console.log(`[vtecxnext addGroup] start. group=${group} selfid=${selfid} uids=${uids}`)
    // 入力チェック
    checkUri(group, 'group key')
    //checkNotNull(selfid, 'selfid (hierarchical name under my group alias)')
    // vte.cxへリクエスト
    const method = 'POST'
    const url = `${SERVLETPATH_PROVIDER}${group}?_addgroup${selfid ? '&_selfid=' + selfid : ''}`

    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext addGroup] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    return await getJson(response)
  }

  /**
   * add group by admin
   * (not yet joined)
   * @param uids uid list
   * @param group group
   * @param selfid hierarchical name under my group alias
   * @return feed
   */
  addGroupByAdmin = async (uids: string[], group: string, selfid?: string): Promise<Entry[]> => {
    //console.log(`[vtecxnext addGroupByAdmin] start. group=${group} selfid=${selfid} uids=${uids}`)
    // 入力チェック
    checkUri(group, 'group key')
    checkNotNull(uids, 'uid')
    //checkNotNull(selfid, 'selfid (hierarchical name under my group alias)')
    // vte.cxへリクエスト
    const method = 'POST'
    const url = `${SERVLETPATH_PROVIDER}${group}?_addgroupByAdmin${selfid ? '&_selfid=' + selfid : ''}`
    const feed = []
    for (const uid of uids) {
      const entry = { link: [{ ___rel: 'self', ___href: `/_user/${uid}` }] }
      feed.push(entry)
    }
    const value = JSON.stringify(feed)

    let response: Response
    try {
      response = await this.requestVtecx(method, url, value)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext addGroupByAdmin] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    return await getJson(response)
  }

  /**
   * join to the group
   * @param group group
   * @param selfid hierarchical name under my group alias
   * @return feed
   */
  joinGroup = async (group: string, selfid?: string): Promise<Entry> => {
    //console.log(`[vtecxnext joinGroup] start. group=${group} selfid=${selfid}`)
    // 入力チェック
    checkUri(group)
    //checkNotNull(selfid, 'selfid (hierarchical name under my group alias)')
    // vte.cxへリクエスト
    const method = 'PUT'
    const url = `${SERVLETPATH_PROVIDER}${group}?_joingroup${selfid ? '&_selfid=' + selfid : ''}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext joinGroup] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    return await getJson(response)
  }

  /**
   * leave from the group
   * @param group group
   * @return feed
   */
  leaveGroup = async (group: string): Promise<boolean> => {
    //console.log(`[vtecxnext leaveGroup] start. group=${group}`)
    // 入力チェック
    checkUri(group)
    // vte.cxへリクエスト
    const method = 'PUT'
    const url = `${SERVLETPATH_PROVIDER}${group}?_leavegroup`
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext leaveGroup] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    return true
  }

  /**
   * leave group by admin
   * @param uids uid list
   * @param group group
   * @return feed
   */
  leaveGroupByAdmin = async (uids: string[], group: string): Promise<Entry> => {
    //console.log(`[vtecxnext leaveGroupByAdmin] start. group=${group} uids=${uids}`)
    // 入力チェック
    checkUri(group, 'group key')
    checkNotNull(uids, 'uid')
    // vte.cxへリクエスト
    const method = 'PUT'
    const url = `${SERVLETPATH_PROVIDER}${group}?_leavegroupByAdmin`
    const feed = []
    for (const uid of uids) {
      const entry = { link: [{ ___rel: 'self', ___href: `/_user/${uid}` }] }
      feed.push(entry)
    }
    const value = JSON.stringify(feed)

    let response: Response
    try {
      response = await this.requestVtecx(method, url, value)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext leaveGroupByAdmin] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    return await getJson(response)
  }

  /**
   * Get entries that have entries in a group, but are not in the group.
   * (for entries with no signature or with an incorrect signature, if the user group requires a signature)
   * @param uri group key
   * @return feed (entry array)
   */
  noGroupMember = async (uri: string): Promise<Entry[]> => {
    //console.log('[vtecxnext noGroupMember] start.')
    // キー入力値チェック
    checkUri(uri)
    // vte.cxへリクエスト
    const method = 'GET'
    const url = `${SERVLETPATH_DATA}${uri}?_no_group_member`
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext noGroupMember] response=${response}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    return await getJson(response)
  }

  /**
   * Get groups
   * @param uri group key
   * @return group array
   */
  getGroups = async (): Promise<string[] | null> => {
    //console.log('[vtecxnext getGroups] start.')
    // vte.cxへリクエスト
    const method = 'GET'
    const url = `${SERVLETPATH_DATA}/?_group`
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext getGroups] response=${response}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    const feed = await getJson(response)
    //console.log(`[vtecxnext getGroups] feed=${JSON.stringify(feed)}`)
    if (feed && Array.isArray(feed) && feed.length > 0) {
      const groups: string[] = []
      for (const entry of feed) {
        if (entry.link && entry.link.length > 0) {
          groups.push(entry.link[0].___href)
        }
      }
      return groups
    }
    return null
  }

  /**
   * whether you are in the group
   * @param uri group key
   * @return true/false
   */
  isGroupMember = async (uri: string): Promise<boolean> => {
    //console.log('[vtecxnext noGroupMember] start.')
    // キー入力値チェック
    checkUri(uri)
    // vte.cxへリクエスト
    const method = 'GET'
    const url = `${SERVLETPATH_DATA}${uri}?_is_group_member`
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext noGroupMember] response=${response}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    const data = await getJson(response)
    return data?.feed?.title === 'true' ? true : false
  }

  /**
   * whether you are in the admin group
   * @return true/false
   */
  isAdmin = async (): Promise<boolean> => {
    return await this.isGroupMember('/_group/$admin')
  }

  /**
   * add user
   * @param adduserInfo adduser infomation
   * @param reCaptchaToken reCAPTCHA token
   * @return message feed (uid)
   */
  adduser = async (adduserInfo: AdduserInfo, reCaptchaToken: string): Promise<MessageResponse> => {
    //console.log(`[vtecxnext adduser] start. feed=${feed}`)
    // 入力チェック
    checkNotNull(adduserInfo, 'username')
    checkNotNull(adduserInfo.username, 'username')
    checkNotNull(adduserInfo.pswd, 'pswd')
    const entry = this.convertAdduserInfoToEntry(adduserInfo)
    const feed = [entry]
    // vte.cxへリクエスト
    const method = 'POST'
    const param = reCaptchaToken ? `&g-recaptcha-token=${reCaptchaToken}` : ''
    const url = `${SERVLETPATH_DATA}/?_adduser${param}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(feed))
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext adduser] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return await getJson(response)
  }

  /**
   * convert adduser info to argument entry
   * @param adduserInfo adduser info
   * @param isNoPswd パスワードを付加しない場合true(passresetの場合true)
   * @returns entry
   */
  private convertAdduserInfoToEntry = (adduserInfo: AdduserInfo, isNoPswd?: boolean): Entry => {
    const retEntry:Entry = {
      contributor: [
        {
          uri: `urn:vte.cx:auth:${this.null2blank(adduserInfo.username)}${isNoPswd ? '' : ',' + this.null2blank(adduserInfo.pswd)}`,
          name: adduserInfo.nickname
        }
      ],
      title: adduserInfo.emailSubject,
      summary: adduserInfo.emailText
    }
    if (adduserInfo.emailHtml) {
      retEntry.content = { ______text: adduserInfo.emailHtml }
    }
    return retEntry
  }

  /**
   * add user by user admin
   * @param feed entries (JSON)
   * @return message feed
   */
  adduserByAdmin = async (adduserInfos: AdduserInfo[]): Promise<MessageResponse> => {
    //console.log(`[vtecxnext adduserByAdmin] start. feed=${feed}`)
    // 入力チェック
    checkNotNull(adduserInfos, 'username')
    const feed: Entry[] = []
    for (const adduserInfo of adduserInfos) {
      const entry = this.convertAdduserInfoToEntry(adduserInfo)
      feed.push(entry)
    }
    // vte.cxへリクエスト
    const method = 'POST'
    const url = `${SERVLETPATH_DATA}/?_adduserByAdmin`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(feed))
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext adduserByAdmin] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return await getJson(response)
  }

  /**
   * add user by group admin
   * @param feed entries (JSON)
   * @param groupname group name
   * @return message feed
   */
  adduserByGroupadmin = async (adduserInfos: AdduserInfo[], groupname: string): Promise<MessageResponse> => {
    //console.log(`[vtecxnext adduserByGroupadmin] start. feed=${feed}`)
    // 入力チェック
    checkNotNull(adduserInfos, 'username')
    checkNotNull(groupname, 'group name')
    const feed: Entry[] = []
    for (const adduserInfo of adduserInfos) {
      const entry = this.convertAdduserInfoToEntry(adduserInfo)
      feed.push(entry)
    }
    // vte.cxへリクエスト
    const method = 'POST'
    const url = `${SERVLETPATH_DATA}/?_adduserByGroupadmin=${groupname}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(feed))
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext adduserByGroupadmin] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return await getJson(response)
  }

  /**
   * Send email for password reset
   * @param adduserInfo mailaddress
   * @param reCaptchaToken reCAPTCHA token
   * @return message feed
   */
  passreset = async (adduserInfo: AdduserInfo, reCaptchaToken?: string): Promise<MessageResponse> => {
    //console.log(`[vtecxnext passreset] start. feed=${feed}`)
    // 入力チェック
    checkNotNull(adduserInfo, 'email address')
    const entry = this.convertAdduserInfoToEntry(adduserInfo, true)
    const feed = [entry]
    // vte.cxへリクエスト
    const method = 'POST'
    const param = reCaptchaToken ? `&g-recaptcha-token=${reCaptchaToken}` : ''
    const url = `${SERVLETPATH_DATA}/?_passreset${param}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(feed))
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext passreset] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return await getJson(response)
  }

  /**
   * change password
   * @param newpswd new password
   * @param oldpswd old password
   * @param passresetToken password reset token
   * @param rxid RXID
   * @return message feed
   */
  changepass = async (newpswd: string, oldpswd?: string, passresetToken?: string, rxid?: string): Promise<MessageResponse> => {
    //console.log(`[vtecxnext changepass] start. feed=${feed}`)
    // 入力チェック
    checkNotNull(newpswd, 'new password')
    const contributors = []
    const newPswdContributor = { uri: `urn:vte.cx:auth:,${newpswd}` }
    contributors.push(newPswdContributor)
    if (oldpswd) {
      const oldPswdContributor = { uri: `urn:vte.cx:oldphash:${oldpswd}` }
      contributors.push(oldPswdContributor)
    }
    if (passresetToken) {
      const passresetTokenContributor = { uri: `urn:vte.cx:passreset_token:${passresetToken}` }
      contributors.push(passresetTokenContributor)
    }
    const feed = [{ contributor: contributors }]
    // vte.cxへリクエスト
    const method = 'PUT'
    const url = `${SERVLETPATH_DATA}/?_changephash${rxid ? '&_RXID=' + rxid : ''}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(feed))
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext changepass] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return await getJson(response)
  }

  /**
   * change password by user admin
   * @param changepassByAdminInfos password change information (uid, password)
   * @return message feed
   */
  changepassByAdmin = async (changepassByAdminInfos: ChangepassByAdminInfo[]): Promise<MessageResponse> => {
    //console.log(`[vtecxnext changepassByAdmin] start. changepassByAdminInfos=${JSON.stringify(changepassByAdminInfos)}`)
    // 入力チェック
    checkNotNull(changepassByAdminInfos, 'password change information')
    const feed: Entry[] = []
    for (const changepassByAdminInfo of changepassByAdminInfos) {
      // 入力チェック
      checkNotNull(changepassByAdminInfo.uid, 'password change information')
      checkNotNull(changepassByAdminInfo.pswd, 'password change information')

      const entry:Entry = {
        contributor: [{ uri: `urn:vte.cx:auth:,${changepassByAdminInfo.pswd}` }],
        link: [{ ___rel: 'self', ___href: `/_user/${changepassByAdminInfo.uid}/auth` }]
      }
      feed.push(entry)
    }
    // vte.cxへリクエスト
    const method = 'PUT'
    const url = `${SERVLETPATH_DATA}/?_changephashByAdmin`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(feed))
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext changepassByAdmin] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return await getJson(response)
  }

  /**
   * change login user's account
   * @param adduserInfo change user info
   * @return message feed
   */
  changeaccount = async (adduserInfo: AdduserInfo): Promise<MessageResponse> => {
    //console.log(`[vtecxnext changeaccount] start. feed=${feed}`)
    // 入力チェック
    checkNotNull(adduserInfo, 'user info')
    const entry = this.convertAdduserInfoToEntry(adduserInfo)
    const feed = [entry]
    // vte.cxへリクエスト
    const method = 'PUT'
    const url = `${SERVLETPATH_DATA}/?_changeaccount`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(feed))
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext changeaccount] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return await getJson(response)
  }

  /**
   * verify to change login user's account
   * @param verifyCode verify code
   * @return message feed
   */
  changeaccount_verify = async (verifyCode: string): Promise<MessageResponse> => {
    //console.log(`[vtecxnext changeaccount_verify] start. verifyCode=${verifyCode}`)
    // 入力値チェック
    checkNotNull(verifyCode, 'verify code')
    // vte.cxへリクエスト
    const method = 'PUT'
    const url = `${SERVLETPATH_DATA}/?_changeaccount_verify=${verifyCode}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext changeaccount_verify] response=${response}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    return await getJson(response)
  }

  /**
   * get user status
   * @param account account
   * @return user status
   */
  userstatus = async (account?: string): Promise<string | Entry[]> => {
    //console.log('[vtecxnext userstatus] start.')
    // vte.cxへリクエスト
    const method = 'GET'
    const url = `${SERVLETPATH_DATA}/?_userstatus${account ? '=' + account : ''}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext userstatus] response=${response}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    const retJson = await getJson(response)
    // 戻り値
    if (account && retJson) {
      return retJson.summary
    }
    return retJson
  }

  /**
   * revoke user
   * @param account account
   * @param isDeleteGroups true if delete groups
   * @return message feed
   */
  revokeuser = async (account: string, isDeleteGroups?: boolean): Promise<Entry> => {
    //console.log('[vtecxnext revokeuser] start.')
    // 入力値チェック
    checkNotNull(account, 'account')
    // vte.cxへリクエスト
    const method = 'PUT'
    const url = `${SERVLETPATH_PROVIDER}/?_revokeuser=${account}${isDeleteGroups ? '&_deletegroup=true' : ''}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext revokeuser] response=${response}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    return await getJson(response)
  }

  /**
   * revoke users
   * @param accounts account list
   * @param uids uid list
   * @param isDeleteGroups true if delete groups
   * @return message feed
   */
  revokeusers = async (
    accounts?: string[],
    uids?: string[],
    isDeleteGroups?: boolean
  ): Promise<Entry[]> => {
    //console.log(`[vtecxnext revokeusers] start. feed=${feed}`)
    // 入力チェック
    if (isBlank(accounts) && isBlank(uids)) {
      throw new VtecxNextError(400, `account or uid is required.`)
    }
    const feed: Entry[] = []
    if (accounts) {
      for (const account of accounts) {
        const entry = { title: account }
        feed.push(entry)
      }
    }
    if (uids) {
      for (const uid of uids) {
        const entry = { link: [{ ___rel: 'self', ___href: `/_user/${uid}` }] }
        feed.push(entry)
      }
    }
    // vte.cxへリクエスト
    const method = 'PUT'
    const url = `${SERVLETPATH_PROVIDER}/?_revokeuser${isDeleteGroups ? '&_deletegroup=true' : ''}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(feed))
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext revokeusers] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return await getJson(response)
  }

  /**
   * activate user
   * @param account account
   * @return message feed
   */
  activateuser = async (account: string): Promise<Entry> => {
    //console.log('[vtecxnext activateuser] start.')
    // 入力値チェック
    checkNotNull(account, 'account')
    // vte.cxへリクエスト
    const method = 'PUT'
    const url = `${SERVLETPATH_PROVIDER}/?_activateuser=${account}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext activateuser] response=${response}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    return await getJson(response)
  }

  /**
   * activate users
   * @param accounts account list
   * @param uids uid list
   * @return message feed
   */
  activateusers = async (accounts?: string[], uids?: string[]): Promise<Entry[]> => {
    //console.log(`[vtecxnext activateusers] start. feed=${feed}`)
    // 入力チェック
    if (isBlank(accounts) && isBlank(uids)) {
      throw new VtecxNextError(400, `account or uid is required.`)
    }
    const feed: Entry[] = []
    if (accounts) {
      for (const account of accounts) {
        const entry = { title: account }
        feed.push(entry)
      }
    }
    if (uids) {
      for (const uid of uids) {
        const entry = { link: [{ ___rel: 'self', ___href: `/_user/${uid}` }] }
        feed.push(entry)
      }
    }
    // vte.cxへリクエスト
    const method = 'PUT'
    const url = `${SERVLETPATH_PROVIDER}/?_activateuser`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(feed))
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext activateusers] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return await getJson(response)
  }

  /**
   * cancel user.
   * @param isDeleteGroups true if delete groups
   * @return message feed
   */
  canceluser = async (isDeleteGroups?: boolean): Promise<MessageResponse> => {
    //console.log('[vtecxnext canceluser] start.')
    // vte.cxへリクエスト
    const method = 'DELETE'
    const url = `${SERVLETPATH_DATA}/?_canceluser${isDeleteGroups ? '&_deletegroup=true' : ''}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext canceluser] response=${response}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    return await getJson(response)
  }

  /**
   * delete user
   * @param account account
   * @return message feed
   */
  deleteuser = async (account: string): Promise<MessageResponse> => {
    //console.log('[vtecxnext deleteuser] start.')
    // 入力値チェック
    checkNotNull(account, 'account')
    // vte.cxへリクエスト
    const method = 'DELETE'
    const url = `${SERVLETPATH_DATA}/?_deleteuser=${account}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext deleteuser] response=${response}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    return await getJson(response)
  }

  /**
   * revoke users
   * @param accounts account list
   * @param uids uid list
   * @return message feed
   */
  deleteusers = async (accounts?: string[], uids?: string[]): Promise<MessageResponse> => {
    //console.log(`[vtecxnext deleteusers] start. accounts=${accounts ? JSON.stringify(accounts) : 'undefined'} uids=${uids ? JSON.stringify(uids) : 'undefined'}`)
    // 入力チェック
    if (isBlank(accounts) && isBlank(uids)) {
      throw new VtecxNextError(400, `account or uid is required.`)
    }
    const feed: Entry[] = []
    if (accounts) {
      for (const account of accounts) {
        const entry = { title: account }
        feed.push(entry)
      }
    }
    if (uids) {
      for (const uid of uids) {
        const entry = { link: [{ ___rel: 'self', ___href: `/_user/${uid}` }] }
        feed.push(entry)
      }
    }
    // vte.cxへリクエスト
    const method = 'DELETE'
    const url = `${SERVLETPATH_DATA}/?_deleteuser`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(feed))
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext deleteusers] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return await getJson(response)
  }

  /**
   * add acl
   * @param feed entries
   * @return message
   */
  addacl = async (feed: Entry[]): Promise<MessageResponse> => {
    //console.log('[vtecxnext addacl] start.')
    // 入力チェック
    checkNotNull(feed, 'Feed')
    // vte.cxへリクエスト
    const method = 'PUT'
    const url = `${SERVLETPATH_DATA}/?_addacl`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(feed))
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext addacl] response=${response}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    return await getJson(response)
  }

  /**
   * remove acl
   * @param feed entries
   * @return message
   */
  removeacl = async (feed: Entry[]): Promise<MessageResponse> => {
    //console.log('[vtecxnext removeacl] start.')
    // 入力チェック
    checkNotNull(feed, 'Feed')
    // vte.cxへリクエスト
    const method = 'PUT'
    const url = `${SERVLETPATH_DATA}/?_removeacl`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(feed))
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext removeacl] response=${response}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    return await getJson(response)
  }

  /**
   * add alias
   * @param feed entries
   * @return message
   */
  addalias = async (feed: Entry[]): Promise<MessageResponse> => {
    //console.log('[vtecxnext addalias] start.')
    // 入力チェック
    checkNotNull(feed, 'Feed')
    // vte.cxへリクエスト
    const method = 'PUT'
    const url = `${SERVLETPATH_DATA}/?_addalias`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(feed))
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext addalias] response=${response}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    return await getJson(response)
  }

  /**
   * remove alias
   * @param feed entries
   * @return message
   */
  removealias = async (feed: Entry[]): Promise<MessageResponse> => {
    //console.log('[vtecxnext removealias] start.')
    // 入力チェック
    checkNotNull(feed, 'Feed')
    // vte.cxへリクエスト
    const method = 'PUT'
    const url = `${SERVLETPATH_DATA}/?_removealias`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(feed))
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext removealias] response=${response}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    return await getJson(response)
  }

  /**
   * get content url.
   * @param uri key
   * @return content url
   */
  getcontenturl = async (uri: string): Promise<string> => {
    //console.log(`[vtecxnext getcontenturl] start. uri=${uri}`)
    // キー入力値チェック
    checkUri(uri)
    // urlを構築
    return `${VTECX_URL}${SERVLETPATH_DATA}${uri}`
  }

  /**
   * save files
   * @param uri key
   * @param bysize true if registering with specified size
   * @param saFormData formData by server action
   * @returns message
   */
  savefiles = async (uri: string, bysize?: boolean, saFormData?: FormData): Promise<MessageResponse> => {
    //console.log(`[vtecxnext savefiles] start. uri=${uri}`)
    if (!this.req && !saFormData) {
      throw new VtecxNextError(421, 'Form data is required.')
    }
    // キー入力値チェック
    checkUri(uri)

    type PromiseKeyBuffer = {
      key: string
      promiseBuffer: Promise<ArrayBuffer>
    }

    let formData: FormData
    if (saFormData) {
      formData = saFormData
    } else if (this.req) {
      formData = await this.req.formData()
    } else {
      throw new VtecxNextError(421, 'Form data is required.')
    }
    const promiseKeyBuffers: PromiseKeyBuffer[] = []
    const promises: Promise<Response>[] = []

    // bufferの取得(非同期)
    formData.forEach(async (val: FormDataEntryValue, key: string) => {
      //console.log(`[vtecxnext savefiles] key=${key} val=${val}`)
      if (val instanceof Blob) {
        const promiseBuffer = val.arrayBuffer()
        const promiseKeyBuffer: PromiseKeyBuffer = { key, promiseBuffer }
        promiseKeyBuffers.push(promiseKeyBuffer)
      }
    })

    // vte.cxへリクエスト(buffer取得を待つ。リクエストは非同期。)
    let contentUris: string = ''
    for (const promiseKeyBuffer of promiseKeyBuffers) {
      const key = promiseKeyBuffer.key
      const buffer = await promiseKeyBuffer.promiseBuffer
      const method = 'PUT'
      const contentUri = `${uri}${uri.endsWith('/') ? '' : '/'}${key}`
      const url = `${SERVLETPATH_PROVIDER}${contentUri}?_content${bysize ? '&_bysize' : ''}`
      //console.log(`[vtecxnext savefiles] request. url=${url}`)
      const promiseResponse = this.requestVtecx(method, url, buffer)
      promises.push(promiseResponse)
      // 戻り値用
      contentUris += `${contentUris ? ', ' : ''}${contentUri}`
    }

    // レスポンス取得
    const msg: string = ''
    for (const promise of promises) {
      const response = await promise
      //console.log(`[vtecxnext savefiles] response. status=${response.status}`)
      // vte.cxからのset-cookieを転記
      this.setCookie(response)
      // レスポンスのエラーチェック
      await checkVtecxResponse(response)
    }
    return { feed: { title: contentUris } }
  }

  /**
   * save files registering with specified size
   * @param uri key
   * @param saFormData formData by server action
   * @returns message
   */
  savefilesBySize = async (uri: string, saFormData?: FormData): Promise<MessageResponse> => {
    return this.savefiles(uri, true, saFormData)
  }

  /**
   * upload content
   * @param uri key
   * @param bysize true if registering with specified size
   * @param filename attachment file name
   * @param arrayBuffer content (for batch or server action)
   * @return message
   */
  putcontent = async (uri: string, filename?: string, arrayBuffer?: ArrayBuffer): Promise<Entry[]> => {
    return this.putcontentProc(uri, false, filename, arrayBuffer)
  }

  /**
   * upload content
   * @param uri key
   * @param bysize true if registering with specified size
   * @param filename attachment file name
   * @param arrayBuffer content (for batch or server action)
   * @return message
   */
  private putcontentProc = async (
    uri: string,
    bysize?: boolean,
    filename?: string,
    arrayBuffer?: ArrayBuffer
  ): Promise<Entry[]> => {
    //console.log(`[vtecxnext putcontent] start. uri=${uri} content-type:${req.headers['content-type']} content-length:${req.headers['content-length']}`)
    if (!this.req && !arrayBuffer) {
      throw new VtecxNextError(421, 'Request is required.')
    }
    // キー入力値チェック
    checkUri(uri)
    // vte.cxへリクエスト
    const method = 'PUT'
    const url = `${SERVLETPATH_PROVIDER}${uri}?_content${bysize ? '&_bysize' : ''}`
    //console.log(`[vtecxnext putcontent] request. url=${url}`)
    const headers: any = { 'Content-Type': this.req?.headers.get('content-type') }
    if (filename) {
      headers['Content-Disposition'] = `attachment; filename="${encodeURIComponent(filename)}"`
    }
    let buf
    if (this.req) {
      buf = await this.req.arrayBuffer()
    } else if (arrayBuffer) {
      buf = arrayBuffer
    }
    let response: Response
    try {
      response = await this.requestVtecx(method, url, buf, headers)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext putcontent] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return await getJson(response)
  }

  /**
   * upload content registering with specified size
   * @param uri key
   * @param arrayBuffer file array buffer by server action
   * @return message
   */
  putcontentBySize = async (uri: string, arrayBuffer?: ArrayBuffer): Promise<Entry[]> => {
    return this.putcontentProc(uri, true, undefined, arrayBuffer)
  }

  /**
   * upload content and numbering
   * @param parenturi parent key
   * @param extension extension
   * @param filename attachment file name
   * @param arrayBuffer file array buffer by server action
   * @return numbered key
   */
  postcontent = async (parenturi: string, extension?: string, filename?: string, arrayBuffer?: ArrayBuffer): Promise<Entry[]> => {
    //console.log(`[vtecxnext postcontent] start. parenturi=${parenturi} extension=${extension} filename=${filename}`)
    if (!this.req && !arrayBuffer) {
      throw new VtecxNextError(421, 'Request is required.')
    }
    // キー入力値チェック
    checkUri(parenturi)
    // vte.cxへリクエスト
    const method = 'POST'
    const url = `${SERVLETPATH_PROVIDER}${parenturi}?_content${extension ? '&_ext=' + extension : ''}`
    //console.log(`[vtecxnext postcontent] request. url=${url}`)
    const headers: any = { 'Content-Type': this.req?.headers.get('content-type') }
    if (filename) {
      headers['Content-Disposition'] = `attachment; filename="${encodeURIComponent(filename)}"`
    }
    //const buf = await buffer(this.req)
    let buf
    if (this.req) {
      buf = await this.req.arrayBuffer()
    } else if (arrayBuffer) {
      buf = arrayBuffer
    }
    let response: Response
    try {
      response = await this.requestVtecx(method, url, buf, headers)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext postcontent] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return await getJson(response)
  }

  /**
   * delete content
   * @param uri key
   * @return message
   */
  deletecontent = async (uri: string): Promise<Entry> => {
    //console.log(`[vtecxnext deletecontent] start. uri=${uri}`)
    // キー入力値チェック
    checkUri(uri)
    // vte.cxへリクエスト
    const method = 'DELETE'
    const url = `${SERVLETPATH_PROVIDER}${uri}?_content`
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext deletecontent] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return await getJson(response)
  }

  /**
   * get content.
   * Writes a content to the response.
   * @param uri key
   * @return true
   */
  getcontent = async (uri: string): Promise<boolean> => {
    //console.log(`[vtecxnext getcontent] start. uri=${uri}`)
    // キー入力値チェック
    checkUri(uri)
    // vte.cxへリクエスト
    const method = 'GET'
    const url = `${SERVLETPATH_PROVIDER}${uri}?_content`
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext getcontent] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    //console.log(`[vtecxnext getcontent] setCookie end.`)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    //console.log(`[vtecxnext getcontent] checkVtecxResponse end.`)
    // 戻り値
    const resData = await response.blob()
    this.setResponseHeaders(response)
    this.resStatus = response.status
    //console.log(`[vtecxnext getcontent] resStatus=${this.resStatus}`)
    if (this.resStatus !== 204) {
      this.bufferData = await resData.arrayBuffer()
      //res.end(new Uint8Array(contentData))
    } else {
      //res.end()
    }
    return this.resStatus === 200
  }

  /**
   * get signed url for upload content
   * @param uri key
   * @param filename attachment file name
   * @return message
   */
  getSignedUrlToPutContent = async (uri: string, filename?: string): Promise<ContentSignedUrl> => {
    //console.log(`[vtecxnext getSignedUrlToPutContent] start. uri=${uri} content-type:${req.headers['content-type']} content-length:${req.headers['content-length']}`)
    // キー入力値チェック
    checkUri(uri)
    // vte.cxへリクエスト
    const method = 'PUT'
    const url = `${SERVLETPATH_PROVIDER}${uri}?_content&_signedurl`
    //console.log(`[vtecxnext getSignedUrlToPutContent] request. url=${url}`)
    const headers: any = { 'Content-Type': this.req?.headers?.get('content-type') }
    if (filename) {
      headers['Content-Disposition'] = `attachment; filename="${encodeURIComponent(filename)}"`
    }
    let response: Response
    try {
      response = await this.requestVtecx(method, url, undefined, headers)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext getSignedUrlToPutContent] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    const resData = await getJson(response)
    return {
      url: resData.feed.title,
      key: resData.feed.subtitle
    }
  }

  /**
   * get signed url for upload content and numbering
   * @param parenturi parent key
   * @param extension extension
   * @return numbered key
   */
  getSignedUrlToPostContent = async (
    parenturi: string,
    extension?: string,
    filename?: string
  ): Promise<ContentSignedUrl> => {
    //console.log(`[vtecxnext getSignedUrlToPostContent] start. parenturi=${parenturi} content-type:${req.headers['content-type']} content-length:${req.headers['content-length']}`)
    // キー入力値チェック
    checkUri(parenturi)
    // vte.cxへリクエスト
    const method = 'POST'
    const url = `${SERVLETPATH_PROVIDER}${parenturi}?_content&_signedurl${extension ? '&_ext=' + extension : ''}`
    //console.log(`[vtecxnext getSignedUrlToPostContent] request. url=${url}`)
    const headers: any = { 'Content-Type': this.req?.headers?.get('content-type') }
    if (filename) {
      headers['Content-Disposition'] = `attachment; filename="${encodeURIComponent(filename)}"`
    }
    let response: Response
    try {
      response = await this.requestVtecx(method, url, undefined, headers)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext getSignedUrlToPostContent] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    const resData = await getJson(response)
    return {
      url: resData.feed.title,
      key: resData.feed.subtitle
    }
  }

  /**
   * get signed url for download content
   * @param uri key
   * @return message
   */
  getSignedUrlToGetContent = async (uri: string): Promise<ContentSignedUrl> => {
    //console.log(`[vtecxnext getSignedUrlToGetContent] start. uri=${uri}`)
    // キー入力値チェック
    checkUri(uri)
    // vte.cxへリクエスト
    const method = 'GET'
    const url = `${SERVLETPATH_PROVIDER}${uri}?_content&_signedurl`
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext getSignedUrlToGetContent] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    const resData = await getJson(response)
    return {
      url: resData.feed.title,
      key: resData.feed.subtitle
    }
  }

  /**
   * OAuth authorization request to LINE.
   * If the OAuth request is successful, this module retains the redirect information.
   */
  oauthLine = async (): Promise<boolean> => {
    const provider = 'line'
    const oauthUrl = 'https://access.line.me/oauth2/v2.1/authorize'
    return await this.oauth(provider, oauthUrl)
  }

  /**
   * OAuth authorization request to LINE
   */
  oauthCallbackLine = async (): Promise<boolean> => {
    // OAuthアクセストークン、OAuth情報を取得
    const provider = 'line'
    const accesstokenUrl = 'https://api.line.me/oauth2/v2.1/token'
    const oauthInfo = await this.oauthGetAccesstoken(provider, accesstokenUrl)

    // ユーザ識別情報を取得
    const userInfo = await this.oauthGetUserinfoLine(oauthInfo)

    // vte.cxユーザと連携・ログイン
    await this.oauthLink(provider, userInfo)
    return true
  }

  /**
   * get TOTP link
   * @param chs length of one side of QR code
   * @return QR code URL in feed.title
   */
  getTotpLink = async (chs?: number): Promise<Entry[]> => {
    //console.log('[vtecxnext getTotpLink] start.')
    // vte.cxへリクエスト
    const method = 'POST'
    const url = `${SERVLETPATH_DATA}/?_createtotp${chs ? '&_chs=' + String(chs) : ''}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext getTotpLink] response=${response}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    return await getJson(response)
  }

  /**
   * create TOTP
   * @param feed one-time password for feed.title when you do book registration
   * @return message
   */
  createTotp = async (feed: LegacyFeed): Promise<MessageResponse> => {
    //console.log('[vtecxnext createTotp] start.')
    // 入力チェック
    checkNotNull(feed, 'Feed')
    // vte.cxへリクエスト
    const method = 'POST'
    const url = `${SERVLETPATH_DATA}/?_createtotp`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(feed))
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext createTotp] response=${response}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    return await getJson(response)
  }

  /**
   * delete TOTP
   * @param account target account (for service admin user)
   * @return message
   */
  deleteTotp = async (account?: string): Promise<MessageResponse> => {
    //console.log('[vtecxnext deleteTotp] start.')
    // vte.cxへリクエスト
    const method = 'DELETE'
    const url = `${SERVLETPATH_DATA}/?_deletetotp${account ? '=' + account : ''}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext deleteTotp] response=${response}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    return await getJson(response)
  }

  /**
   * change TDID (Trusted device ID)
   * @param account target account (for service admin user)
   * @return message
   */
  changeTdid = async (): Promise<MessageResponse> => {
    //console.log('[vtecxnext changeTdid] start.')
    // vte.cxへリクエスト
    const method = 'PUT'
    const url = `${SERVLETPATH_DATA}/?_changetdid`
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext changeTdid] response=${response}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    return await getJson(response)
  }

  /**
   * Merge an existing user with an line oauth user.
   * @param rxid RXID
   * @return user entry
   */
  mergeOAuthUserLine = async (rxid: string): Promise<Entry> => {
    //console.log(`[vtecxnext mergeOAuthUserLine] start. feed=${feed}`)
    return this.mergeOAuthUser('line', rxid)
  }

  /**
   * create group admin
   * @param CreateGroupadminInfo group name and uid list
   * @return message feed
   */
  createGroupadmin = async (createGroupadminInfos: CreateGroupadminInfo[]): Promise<MessageResponse> => {
    //console.log(`[vtecxnext createGroupadmin] start. feed=${feed}`)
    // 入力チェック
    checkNotNull(createGroupadminInfos, 'group name')
    const feed: Entry[] = []
    for (const createGroupadminInfo of createGroupadminInfos) {
      checkNotNull(createGroupadminInfo.group, 'group name')
      checkContainSlash(createGroupadminInfo.group, 'group name')
      checkNotNull(createGroupadminInfo.uids, 'uid')
      const links: Link[] = [{ ___rel: 'self', ___href: `/_group/${createGroupadminInfo.group}` }]
      for (const uid of createGroupadminInfo.uids) {
        const link = { ___rel: 'via', ___title: uid }
        links.push(link)
      }
      const entry = { link: links }
      feed.push(entry)
    }
    // vte.cxへリクエスト
    const method = 'POST'
    const url = `${SERVLETPATH_DATA}/?_creategroupadmin`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(feed))
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext createGroupadmin] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return await getJson(response)
  }

  /**
   * delete group admin group
   * @param groupNames group name list
   * @param async execute async
   * @return message feed
   */
  deleteGroupadmin = async (groupNames: string[], async?: boolean): Promise<MessageResponse> => {
    //console.log(`[vtecxnext deleteGroupadmin] start. feed=${feed}`)
    // 入力チェック
    checkNotNull(groupNames, 'group name')
    const feed: Entry[] = []
    for (const groupName of groupNames) {
      checkNotNull(groupName, 'group name')
      checkContainSlash(groupName, 'group name')
      const links: Link[] = [{ ___rel: 'self', ___href: `/_group/${groupName}` }]
      const entry = { link: links }
      feed.push(entry)
    }
    // vte.cxへリクエスト
    const method = 'DELETE'
    const url = `${SERVLETPATH_DATA}/?_deletegroupadmin${async ? '&_async' : ''}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(feed))
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext deleteGroupadmin] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return await getJson(response)
  }

  /**
   * get property
   * @param name property name
   * @return property value
   */
  property = async (name: string): Promise<string | null> => {
    //console.log('[vtecxnext property] start.')
    // 入力チェック
    checkNotNull(name, 'Name')
    // vte.cxへリクエスト
    const method = 'GET'
    const url = `${SERVLETPATH_PROVIDER}/?_property=${name}`
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext property] response=${response}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    // 戻り値
    if (response.status === 204) {
      return null
    }
    const data = await getJson(response)
    return data.feed.title
  }

  //----------------------
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
  private requestVtecx = async (
    method: string,
    url: string,
    body?: any,
    additionalHeaders?: any,
    targetService?: string,
    mode?: RequestMode
  ): Promise<Response> => {
    // cookieの値をvte.cxへのリクエストヘッダに設定
    const cookie = await this.editRequestCookie()
    //console.log(`[requestVtecx] cookie = ${cookie}`)
    const headers: any = cookie ? { Cookie: cookie } : {}
    if (this.accessToken) {
      headers.Authorization = `Token ${this.accessToken}`
    }
    if (additionalHeaders) {
      //console.log(`[vtecxnext requestVtecx] additionalHeaders for`)
      for (const key in additionalHeaders) {
        headers[key] = additionalHeaders[key]
      }
    }
    if (targetService) {
      // サービス連携の場合
      let servicekey = process.env[`SERVICEKEY_${targetService}`]
      if (!servicekey) {
        const max = 10
        for (let i = 1; i <= max; i++) {
          const iStr = String(i)
          const tmpServiceName = process.env[`SERVICELINKAGE_${iStr}`]
          if (targetService == tmpServiceName) {
            servicekey = process.env[`SERVICEKEY_${iStr}`]
            break
          }
        }
      }
      //console.log(`[requestVtecx] targetService=${targetService} servicekey=${servicekey}`)
      headers['X-SERVICELINKAGE'] = targetService
      if (servicekey) {
        headers['X-SERVICEKEY'] = servicekey
      }
    }
    return fetchVtecx(method, url, headers, body, mode)
  }

  /**
   * vte.cxからのset-cookieを、ブラウザへレスポンスする。
   * @param response vte.cxからのレスポンス
   */
  private setCookie = (response: Response): void => {
    try {
      // set-cookieの値をレスポンスヘッダ格納変数にセット
      let setCookieVal = response.headers.get('set-cookie')
      if (setCookieVal === '' || setCookieVal) {
        //console.log(`[vtecxnext setCookie] setCookieVal=${setCookieVal}`)
        this.resHeaders['set-cookie'] = setCookieVal
        if (this.cookieStore) {
          // server action用
          //console.log(`[vtecxnext setCookie] server action用`)
          const idx = setCookieVal.indexOf('=')
          const name = setCookieVal.substring(0, idx)
          const parts = setCookieVal.substring(idx + 1).split(';')
          // 最初は値
          const value = parts[0]
          const options:{[name:string]: any} = {
            'name': name,
            'value': value
          }

          const len = parts.length
          for (let i = 1; i < len; i++) {
            const tmp = parts[i].trim()
            const tmpIdx = tmp.indexOf('=')
            let tmpName:string
            let tmpVal:string
            if (tmpIdx > 0) {
              tmpName = tmp.substring(0, tmpIdx)
              tmpVal = tmp.substring(tmpIdx + 1)
            } else {
              tmpName = tmp
              tmpVal = ''
            }
            // 先頭を小文字にする
            tmpName = `${tmpName.substring(0, 1).toLocaleLowerCase()}${tmpName.substring(1)}`
            if (tmpName === 'expires') {
              options['expires'] = new Date(tmpVal)
            } else if (tmpName === 'maxAge' || tmpName === 'max-Age') {
              options['maxAge'] = Number(tmpVal)
            } else if (tmpVal === '') {
              options[tmpName] = true
            } else {
              options[tmpName] = tmpVal
            }
          }
          //console.log(`[vtecxnext setCookie] options=${JSON.stringify(options)}`)
          this.cookieStore.set(options)
        }
      }
    } catch (e) {
      // Server Componentで実行された場合「Cookies can only be modified in a Server Action or Route Handler.」エラーが発生する。
      //console.log(`[vtecxnext setCookie] Error occured. ${e}`)
      // Do nothing.
    }
  }

  /**
   * ログイン時にレスポンスされたvte.cxからのset-cookieを保持する。
   * @param response vte.cxからのレスポンス
   */
  private setLoginCookie = (response: Response): void => {
    // set-cookieの値をレスポンスヘッダ格納変数にセット
    let setCookieVal = response.headers.get('set-cookie')
    if (setCookieVal) {
      const tmpCookies = setCookieVal.split(';')
      for (const tmpCookie of tmpCookies) {
        const tmpKeyVal = tmpCookie.split('=')
        this.loginCookies[tmpKeyVal[0]] = tmpKeyVal[1]
      }
    }
  }

  /**
   * ログイン後のCookie編集
   * @returns cookie
   */
  private editRequestCookie = async (): Promise<string | null> => {
    //console.log(`[editRequestCookie] start.`)
    let cookie = this.req ? this.req.headers.get('cookie') : null
    if (!this.loginCookies) {
      return cookie
    }
    let retCookie: string = ''
    if (cookie) {
      const tmpCookies = cookie.split(';')
      for (const tmpCookie of tmpCookies) {
        const tmpKeyVal = tmpCookie.trim().split('=')
        const tmpName = tmpKeyVal[0]
        const tmpVal = tmpKeyVal[1]
        if (!this.loginCookies.hasOwnProperty(tmpName)) {
          retCookie = `${retCookie}${tmpName}=${tmpVal}; `
        }
      }
    } else {
      if (this.shouldBeCreatedCookieStore) {
        //console.log(`[editRequestCookie] shouldBeCreatedCookieStore === true`)
        try {
          this.cookieStore = await cookies()
        } catch (e) {
          // Do nothing.
          //console.log(`[editRequestCookie] Error occured by await cookies() : ${e}`)
        }
        this.shouldBeCreatedCookieStore = false
      }
      if (this.cookieStore) {
        //console.log(`[editRequestCookie] this.cookieStore === true. ${JSON.stringify(this.cookieStore)}`)
        // server action用
        const cookieArray = this.cookieStore.getAll()
        if (cookieArray && cookieArray.length > 0) {
          for (const tmpCookie of cookieArray) {
            if (!this.loginCookies.hasOwnProperty(tmpCookie.name)) {
              retCookie = `${retCookie}${tmpCookie.name}=${tmpCookie.value}; `
            }
          }
        }
      }
    }
    for (const tmpName in this.loginCookies) {
      const tmpVal = this.loginCookies[tmpName]
      retCookie = `${retCookie}${tmpName}=${tmpVal};`
    }
    return retCookie
  }

  /**
   * vte.cxからのレスポンスヘッダを、ブラウザへレスポンスする。
   * コンテンツの戻し時に使用。
   * @param response vte.cxからのレスポンス
   * @param res ブラウザへのレスポンス
   */
  private setResponseHeaders = (response: Response): void => {
    const it = response.headers.entries()
    let header: IteratorResult<[string, string], any> = it.next()
    while (header && !header.done) {
      const name = header.value[0]
      if (name.startsWith('content-') || name.startsWith('x-')) {
        const val = header.value[1]
        //console.log(`[vtecxnext setResponseHeaders] ${name} = ${val}`)
        this.resHeaders[name] = val
      }
      header = it.next()
    }
  }

  /**
   * OAuth authorization request
   * @param provider OAuth provider name
   * @param oauthUrl OAuth authorization request url
   * @return true
   */
  private oauth = async (provider: string, oauthUrl: string): Promise<boolean> => {
    //console.log(`[vtecxnext oauth] start. provider=${provider} oauthUrl=${oauthUrl}`)
    if (!this.req) {
      throw new VtecxNextError(421, 'Request is required.')
    }

    // TODO reCAPTCHAを必須とすべき?

    // 入力チェック
    checkNotNull(provider, 'OAuth provider')
    // vte.cxへリクエスト (state取得)
    const method = 'POST'
    const url = `${SERVLETPATH_OAUTH}/${provider}/create_state`
    let response: Response
    try {
      response = await this.requestVtecx(method, url)
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
    //res.setHeader('Location', authorizationUrl)
    this.setResponseHeader('Location', authorizationUrl)
    //res.setHeader('Access-Control-Allow-Origin', origin)
    //res.setHeader('Access-Control-Allow-Method', 'GET, OPTIONS')
    //console.log(`[vtecxnext oauth] response headers=${JSON.stringify(res.getHeaders())}`)
    //res.writeHead(302)
    this.resStatus = 302
    //res.end()
    return true
  }

  /**
   * OAuth authorization request
   * @param provider OAuth provider name
   * @param oauthUrl OAuth get accesstoken request url
   * @return {'client_id', 'client_secret', 'redirect_uri', 'state', 'access_token'}
   */
  private oauthGetAccesstoken = async (provider: string, accesstokenUrl: string): Promise<OAuthInfo> => {
    //console.log(`[vtecxnext oauthGetAccesstoken] start. provider=${provider} oauthUrl=${accesstokenUrl}`)
    if (!this.req) {
      throw new VtecxNextError(421, 'Request is required.')
    }

    // stateチェック
    //const parseUrl = urlmodule.parse(this.req.url ?? '', true)
    //const state = parseUrl.query.state
    //const code = parseUrl.query.code
    const url = this.req.nextUrl
    const searchParams = url.searchParams
    const state = searchParams.get('state')
    const code = searchParams.get('code')

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
    let vtecxResponse: Response
    try {
      vtecxResponse = await this.requestVtecx(vtecxMethod, vtecxUrl)
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext oauthGetAccesstoken] check_state response status=${vtecxResponse.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(vtecxResponse)
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
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: redirect_uri,
      client_id: client_id,
      client_secret: client_secret
    }
    const accesstokenBody = createURLSearchParams(accessTokenData).toString()

    //const accesstokenBodyStr = `grant_type=authorization_code&code=${code}&redirect_uri=${encodeRedirect_uri}&client_id=${client_id}&client_secret=${client_secret}`
    //console.log(`[vtecxnext oauthGetAccesstoken] accesstokenUrl=${accesstokenUrl}`)
    //console.log(`[vtecxnext oauthGetAccesstoken] accesstokenBodyStr=${accesstokenBodyStr}`)
    //const accesstokenBody = Buffer.from(accesstokenBodyStr, 'utf-8')
    const requestInit: RequestInit = {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': String(accesstokenBody.length)
      },
      body: accesstokenBody,
      method: accesstokenMethod,
      cache: 'no-cache'
    }

    let accesstokenResponse: Response
    try {
      accesstokenResponse = await fetchProc(accesstokenUrl, requestInit)
    } catch (e) {
      throw newFetchError(e, false)
    }
    if (accesstokenResponse.status !== 200) {
      const errorInfo = await accesstokenResponse.json()
      //console.log(`[vtecxnext oauthGetAccesstoken] Get accesstoken failed. ${JSON.stringify(errorInfo)}`)
      const errMsg = `${'error' in errorInfo ? errorInfo.error + '. ' : ''} ${'error_description' in errorInfo ? errorInfo.error_description : ''}`
      throw new VtecxNextError(
        401,
        `Get accesstoken failed. status=${accesstokenResponse.status} ${errMsg}`
      )
    }
    const accesstokenInfo = await accesstokenResponse.json()
    const access_token = accesstokenInfo.access_token
    if (!access_token) {
      throw new VtecxNextError(401, `Get accesstoken failed.`)
    }

    return {
      client_id: client_id,
      client_secret: client_secret,
      redirect_uri: redirect_uri,
      state: state,
      access_token: access_token
    }
  }

  /**
   * OAuth get userinfo request
   * @param oauthInfo OAuth info {'client_id', 'client_secret', 'redirect_uri', 'state', 'access_token'}
   * @return userinfo {'guid', 'nickname', 'state'}
   */
  private oauthGetUserinfoLine = async (oauthInfo: OAuthInfo): Promise<OAuthUserInfo> => {
    //console.log(`[vtecxnext oauthGetUserinfoLine] start. oauthInfo=${JSON.stringify(oauthInfo)}`)

    // LINEユーザ識別情報取得リクエスト
    const url = 'https://api.line.me/v2/profile'
    const method = 'GET'
    const headers = { Authorization: `Bearer ${oauthInfo.access_token}` }
    //console.log(`[vtecxnext oauthGetUserinfoLine] url=${url}`)
    const requestInit: RequestInit = {
      headers: headers,
      method: method,
      cache: 'no-cache'
    }
    let response: Response
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
      guid: guid,
      nickname: nickname,
      state: oauthInfo.state
    }
  }

  /**
   * OAuth user link.
   * @param provider OAuth provider name
   * @param userInfo user info
   * @return true if log in has been successful.
   */
  private oauthLink = async (provider: string, userInfo: OAuthUserInfo): Promise<boolean> => {
    //console.log(`[vtecxnext oauthLink] start. userInfo=${JSON.stringify(userInfo)}`)
    // OAuthリンク・ログイン
    // reCAPTCHA tokenは任意
    //const param = reCaptchaToken ? `&g-recaptcha-token=${reCaptchaToken}` : ''
    const param = ''
    const method = 'POST'
    const url = `${SERVLETPATH_OAUTH}/${provider}/link?state=${userInfo.state}${param}`
    const reqFeed = [{ title: userInfo.guid, subtitle: userInfo.nickname }]
    let response: Response
    try {
      response = await fetchVtecx(method, url, {}, JSON.stringify(reqFeed))
    } catch (e) {
      throw newFetchError(e, true)
    }
    const feed = await response.json()
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
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
   * Merge an existing user with an oauth user.
   * @param provider OAuth provider name
   * @param rxid RXID
   * @return user entry
   */
  private mergeOAuthUser = async (provider: string, rxid: string): Promise<Entry> => {
    //console.log(`[vtecxnext mergeOAuthUser] start. feed=${feed}`)
    // 入力チェック
    checkNotNull(provider, 'Provider')
    checkNotNull(rxid, 'RXID')
    // vte.cxへリクエスト
    const method = 'PUT'
    const url = `${SERVLETPATH_DATA}/?_mergeoauthuser`
    const feed = { feed: { subtitle: provider, rights: rxid } }
    let response: Response
    try {
      response = await this.requestVtecx(method, url, JSON.stringify(feed))
    } catch (e) {
      throw newFetchError(e, true)
    }
    //console.log(`[vtecxnext mergeOAuthUser] response. status=${response.status}`)
    // vte.cxからのset-cookieを転記
    this.setCookie(response)
    // レスポンスのエラーチェック
    await checkVtecxResponse(response)
    return await getJson(response)
  }
}

//---------------------------------------------
/**
 * response class
 */
export type VtecxResponse<T = unknown> = {
  status: number
  header: Record<string, string>
  data: T
}
/*
export type VtecxResponse {
  status: number
  header: any
  data: any
  constructor(status: number, header: any, data: any) {
    this.status = status
    this.header = header
    this.data = data
  }
}
*/
/**
 * vtecx response create helper
 * @param status status
 * @param header header
 * @param data data
 * @returns vtecx response object
 */
const vtecxResponse = <T>(
  status: number,
  header: Record<string, string>,
  data: T
): VtecxResponse<T> => ({ status, header, data })

/**
 * Error returned from vte.cx
 */
export class VtecxNextError extends Error {
  status: number
  constructor(status: number, message: string) {
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
  constructor(message: string) {
    super(500, message)
    this.name = 'FetchError'
    //this.url = url
    //this.requestInit = requestInit
  }
}

/**
 * VtecxNextError型かどうかチェック
 * インターフェースの判定には型ガード関数を使う
 * @param value チェックオブジェクト
 * @returns VtecxNextError型の場合true
 */
export const isVtecxNextError = (value: unknown): value is VtecxNextError => {
  // 値がオブジェクトであるかの判定
  if (typeof value !== 'object' || value === null) {
    return false
  }
  const { status, message } = value as Record<keyof VtecxNextError, unknown>
  // statusプロパティーが数値型かを判定
  if (typeof status !== 'number') {
    return false
  }
  // messageプロパティーが文字列型かを判定
  if (typeof message !== 'string') {
    return false
  }
  return true
}

//---------------------------------------------
/**
 * vte.cxへリクエスト
 * @param method メソッド
 * @param url サーブレットパス以降のURL
 * @param pHeaders リクエストヘッダ。連想配列で指定。
 * @param body リクエストデータ
 * @param mode RequestMode ("cors" | "navigate" | "no-cors" | "same-origin")
 * @returns promise
 */
const fetchVtecx = async (
  method: string,
  url: string,
  pHeaders: any,
  body?: any,
  mode?: RequestMode
): Promise<Response> => {
  //console.log(`[vtecxnext fetchVtecx] url=${process.env.VTECX_URL}${url}`)
  const headers: [string, string][] = []
  if (pHeaders) {
    for (const key in pHeaders) {
      //console.log(`[vtecxnext fetchVtecx] request header = ${key}: ${pHeaders[key]}`)
      headers.push([key, pHeaders[key]])
    }
  }
  headers.push(['X-Requested-With', 'XMLHttpRequest'])
  if (VTECX_SERVICENAME) {
    headers.push(['X-SERVICENAME', VTECX_SERVICENAME])
  }
  const apiKey = process.env.VTECX_APIKEY
  if (apiKey && !url.startsWith(SERVLETPATH_DATA)) {
    const apiKeyVal = `APIKey ${apiKey}`
    headers.push(['Authorization', apiKeyVal])
  }

  //console.log(`[vtecxnext fetchVtecx] headers = ${JSON.stringify(headers)}`)
  const requestInit: RequestInit = {
    body: body,
    method: method,
    headers: headers,
    cache: 'no-cache'
  }
  if (mode) {
    requestInit['mode'] = mode
  }

  return fetchProc(`${VTECX_URL}${url}`, requestInit)
}

const newFetchError = (e: any, isVtecx: boolean): FetchError => {
  let errMsg: string
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
const fetchProc = (url: string, requestInit: RequestInit): Promise<Response> => {
  //console.log(`[vtecxnext fetchProc] url=${url}`)
  return fetch(url, requestInit)
}

/**
 * get binary data from stream
 * @param readable Readable
 * @returns buffer
 */
const buffer = async (readable: Readable): Promise<Buffer> => {
  const chunks = []
  for await (const chunk of readable) {
    chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk)
  }
  return Buffer.concat(chunks)
}

/**
 * null、undefined、空文字の判定
 * 配列で空の場合もtrueを返す。
 * @param val チェック値
 * @returns null、undefined、空文字の場合true
 */
const isBlank = (val: any): boolean => {
  if (val === null || val === undefined || val === '') {
    return true
  }
  if (Array.isArray(val) && val.length <= 0) {
    return true
  }
  return false
}

/**
 * vte.cxからのレスポンスが正常かエラーかをチェックする。
 * エラーの場合 VtecxNextError をスローする。
 * @param response Response
 * @returns 戻り値はなし。エラーの場合VtecxNextErrorをスロー。
 */
const checkVtecxResponse = async (response: Response): Promise<void> => {
  //console.log(`[vtecxnext checkVtecxResponse] status=${response.status}`)
  if (response.status < 400 && response.status !== 203) {
    //console.log(`[vtecxnext checkVtecxResponse] return.`)
    return
  } else {
    //console.log(`[vtecxnext checkVtecxResponse] error.`)
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
const checkNotNull = (val: any, name?: string): void => {
  if (isBlank(val)) {
    throw new VtecxNextError(400, `${name ?? 'Key'} is required.`)
  }
}

/**
 * 文字列にスラッシュが含まれている場合エラー
 * エラーの場合 VtecxNextError をスローする。
 * @param val チェック文字列
 * @param name エラーの場合の項目名称
 */
const checkContainSlash = (val: string, name: string): void => {
  if (val.indexOf('/') > -1) {
    throw new VtecxNextError(400, `${name} cannot contain a slash : ${val}`)
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
const checkUri = (str: string|undefined, name?: string): void => {
  checkNotNull(str, name)
  if (!str?.startsWith('/')) {
    throw new VtecxNextError(400, `${name ?? 'Key'} must start with a slash.`)
  }
}

/**
 * レスポンスデータをJSON形式で取得.
 * @param response レスポンス
 * @returns JSON
 */
const getJson = async (response: Response): Promise<any> => {
  // ステータスが204の場合nullを返す。
  if (response.status === 204) {
    return null
  }
  // content-length=0の場合nullを返す
  const contentLength = response.headers.get('content-length')
  if (contentLength === '0') {
    return null
  }
  try {
    return await response.json()
  } catch (e) {
    let errMsg: string
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
const editBqTableNames = (tablenames: {[key: string]: string}|undefined): string|null => {
  //console.log(`[vtecxnext editBqTableNames] tablenames = ${tablenames}`)
  if (!tablenames) {
    return null
  }
  let result = ''
  for (const key in tablenames) {
    const value = tablenames[key]
    //console.log(`[vtecxnext editBqTableNames] ${key}=${value}`)
    result = `${result ? result + ',' : ''}${key}:${value}`
  }
  //console.log(`[vtecxnext editBqTableNames] result=${result}`)
  return result
}

/**
 * SQLインジェクション対策を行い、安全に値を設定した上で、feedにセットします.
 * @param sql SQL
 * @param values SQLに指定する値
 * @param parent 戻り値JSONの親項目(任意)か、CSVのヘッダ(任意)
 * @returns SQLをセットしたfeed
 */
const editSqlArgument = (sql: string, values?: any[], parent?: string): any => {
  // SQLに引数を代入（SQLインジェクション対応）
  const editSql = values ? formatSql(sql, values) : sql
  //console.log(`[vtecxnext editSqlArgument] sql=${editSql}`)
  // 引数
  const entry: any = { title: editSql }
  if (parent) {
    entry['subtitle'] = parent
  }
  const feed: any[] = [entry]
  return feed
}

/**
 * SQLインジェクション対策を行い、安全に値を設定した上で、feedにセットします.
 * @param sqls SQLリスト
 * @param values SQLに指定する値
 * @returns SQLをセットしたfeed
 */
const editSqlsArgument = (sqls: string[], values?: any[][]): any => {
  // SQLに引数を代入（SQLインジェクション対応）
  const len = sqls.length
  let editedSqls: string[]
  if (values) {
    if (sqls.length !== values.length) {
      throw new VtecxNextError(400, ``)
    }
    editedSqls = new Array(len)
    for (let i = 0; i < len; i++) {
      editedSqls[i] = formatSql(sqls[i], values[i])
    }
  } else {
    editedSqls = sqls
  }
  const feed: any[] = []
  let i = 0
  for (const editSql of editedSqls) {
    const entry = { title: editSql }
    feed[i] = entry
    i++
  }
  return feed
}

/**
 * SQLの'?'を指定された引数に置き換える。（SQLインジェクション対応）
 * @param sql SQL
 * @param values 置き換え対象値
 * @returns 値が代入されたSQL
 */
const formatSql = (sql: string, values: any[]): string => {
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
const getLinks = (rel: string, hrefs: string[]): any => {
  if (!rel || !hrefs) {
    return undefined
  }
  const links = []
  let idx = 0
  for (const href of hrefs) {
    const link = { ___rel: rel, ___href: href }
    links[idx] = link
    idx++
  }
  //console.log(`[vtecxnext getLinks] links=${JSON.stringify(links)}`)
  return links
}

/**
 * URLからOriginを取得
 * @param oauthUrl URL
 * @returns Origin
 */
const getOrigin = (oauthUrl: string): string => {
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
const createURLSearchParams = (data: any) => {
  const params = new URLSearchParams()
  Object.keys(data).forEach((key) => params.append(key, data[key]))
  return params
}

/**
 * URIのパラメータ部分を連想配列にして返却
 * @param uri URI
 * @returns パラメータを連想配列にしたオブジェクト
 */
const getParamMap = (uri:string): {[name:string]: string} => {
  if (!uri) {
    return {}
  }
  const idxQ = uri.indexOf('?')
  if (idxQ < 0) {
    return {}
  }
  const paramStr = uri.substring(idxQ + 1)
  if (!paramStr) {
    return {}
  }
  const params:{[name:string]: string} = {}
  const paramStrParts = paramStr.split('&')
  for (const paramStrPart of paramStrParts) {
    let name:string = ''
    let value:string = ''
    const idxE = paramStrPart.indexOf('=')
    if (idxE < 0) {
      name = paramStrPart
    } else {
      name = paramStrPart.substring(0, idxE)
      value = paramStrPart.substring(idxE + 1)
    }
    params[name] = value
  }
  return params
}

/**
 * URIにカーソルを付加
 * @param uri URI
 * @param nextpage カーソル 
 * @returns URIにカーソルを付加した文字列
 */
const addNextpage = (uri:string, nextpage:string):string => {
  if (nextpage) {
    const rchar = uri.indexOf('?') < 0 ? '?' : '&'
    return `${uri}${rchar}${PARAM_NEXTPAGE}=${nextpage}`
  } else {
    return uri
  }
}
