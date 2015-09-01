/*      $NetBSD: ieee80211.h,v 1.26 2013/03/30 14:14:31 christos Exp $  */
/*-
 * Copyright (c) 2001 Atsushi Onoe
 * Copyright (c) 2002-2005 Sam Leffler, Errno Consulting
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/net80211/ieee80211.h,v 1.10 2005/07/22 16:55:27 sam Exp $
 */
#ifndef _NET80211_IEEE80211_H_
#define _NET80211_IEEE80211_H_

#define IEEE80211_FC0_VERSION_MASK              0x03
#define IEEE80211_FC0_VERSION_SHIFT             0
#define IEEE80211_FC0_VERSION_0                 0x00
#define IEEE80211_FC0_TYPE_MASK                 0x0c
#define IEEE80211_FC0_TYPE_SHIFT                2
#define IEEE80211_FC0_TYPE_MGT                  0x00
#define IEEE80211_FC0_TYPE_CTL                  0x04
#define IEEE80211_FC0_TYPE_DATA                 0x08

#define IEEE80211_FC0_SUBTYPE_MASK              0xf0
#define IEEE80211_FC0_SUBTYPE_SHIFT             4
/* for TYPE_MGT */
#define IEEE80211_FC0_SUBTYPE_ASSOC_REQ         0x00
#define IEEE80211_FC0_SUBTYPE_ASSOC_RESP        0x10
#define IEEE80211_FC0_SUBTYPE_REASSOC_REQ       0x20
#define IEEE80211_FC0_SUBTYPE_REASSOC_RESP      0x30
#define IEEE80211_FC0_SUBTYPE_PROBE_REQ         0x40
#define IEEE80211_FC0_SUBTYPE_PROBE_RESP        0x50
#define IEEE80211_FC0_SUBTYPE_BEACON            0x80
#define IEEE80211_FC0_SUBTYPE_ATIM              0x90
#define IEEE80211_FC0_SUBTYPE_DISASSOC          0xa0
#define IEEE80211_FC0_SUBTYPE_AUTH              0xb0
#define IEEE80211_FC0_SUBTYPE_DEAUTH            0xc0
/* for TYPE_CTL */
#define IEEE80211_FC0_SUBTYPE_PS_POLL           0xa0
#define IEEE80211_FC0_SUBTYPE_RTS               0xb0
#define IEEE80211_FC0_SUBTYPE_CTS               0xc0
#define IEEE80211_FC0_SUBTYPE_ACK               0xd0
#define IEEE80211_FC0_SUBTYPE_CF_END            0xe0
#define IEEE80211_FC0_SUBTYPE_CF_END_ACK        0xf0
/* for TYPE_DATA (bit combination) */
#define IEEE80211_FC0_SUBTYPE_DATA              0x00
#define IEEE80211_FC0_SUBTYPE_CF_ACK            0x10
#define IEEE80211_FC0_SUBTYPE_CF_POLL           0x20
#define IEEE80211_FC0_SUBTYPE_CF_ACPL           0x30
#define IEEE80211_FC0_SUBTYPE_NODATA            0x40
#define IEEE80211_FC0_SUBTYPE_CFACK             0x50
#define IEEE80211_FC0_SUBTYPE_CFPOLL            0x60
#define IEEE80211_FC0_SUBTYPE_CF_ACK_CF_ACK     0x70
#define IEEE80211_FC0_SUBTYPE_QOS               0x80
#define IEEE80211_FC0_SUBTYPE_QOS_NULL          0xc0


#endif /* !_NET80211_IEEE80211_H_ */
