/*
 * Copyright (c) 2014-2021 Bjoern Kimminich.
 * SPDX-License-Identifier: MIT
 */

import { environment } from '../../environments/environment'
import { Injectable } from '@angular/core'
import { HttpClient, HttpParams } from '@angular/common/http'
import { catchError, map } from 'rxjs/operators'

@Injectable({
  providedIn: 'root'
})
export class OrderHistoryService {

  private hostServer = environment.hostServer
  private host = this.hostServer + '/rest/order-history'

  constructor (private http: HttpClient) { }

  get (query?: string, status?: string) {
    let params = new HttpParams()
    if (query) {
      params = params.set('q', query)
    }
    if (status) {
      params = params.set('status', status)
    }
    return this.http.get(this.host, { params }).pipe(map((response: any) => response.data), catchError((err) => { throw err }))
  }

  getAll () {
    return this.http.get(this.host + '/orders').pipe(map((response: any) => response.data), catchError((err) => { throw err }))
  }

  toggleDeliveryStatus (id, params) {
    return this.http.put(this.host + '/' + id + '/delivery-status', params).pipe(map((response: any) => response.data), catchError((err) => { throw err }))
  }
}
