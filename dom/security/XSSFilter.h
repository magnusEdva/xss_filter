/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 License, v. 2.0. If a copy of the MPL was not distributed with this
 file, You can obtain one at http://mozilla.org/MPL/2.0/.  */

#ifndef mozilla_dom_XSSFilter_h
#define mozilla_dom_XSSFilter_h

#include "mozilla/Tokenizer.h"
#include <map>
#include <iterator>
#include "mozilla/dom/Document.h"
#include "ScriptLoadRequest.h"
#include "nsCOMPtr.h"
#include "mozilla/dom/URLSearchParams.h"
#include "nsIUploadChannel.h"
#include "nsISeekableStream.h"
#include "nsIHttpChannel.h"
#include "nsIURI.h"

namespace mozilla {
namespace dom {

//////////////////////////////////////////////////////////////
// XSS Filter implementation
//////////////////////////////////////////////////////////////

class XSSFilter {
public:
  XSSFilter();
  bool StartFilter(const nsAString& script, ScriptLoadRequest* request);
  bool StartFilter(const nsAString& script, const nsAString& url);
  bool StartFilter(nsCOMPtr<nsIURI> scriptURI);

private:
  bool isInjected(const nsAString& reqParam, const nsAString& mScriptContent);
  nsresult GetGETData(const nsACString& URL, URLParams& params);
  void TrimRequestData(URLParams& params);
  bool isOnlyAlphaNumeric(nsCString reqParam);


}; // namespace dom
}; // namespace mozilla

#endif // mozilla_dom_XSSFilter_h
