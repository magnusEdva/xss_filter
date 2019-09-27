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

private:
  Document* mDocument;
  nsAutoCString srcFromRequest;
  std::map <nsAutoCString, nsAutoCString> postParams;
  URLParams urlGetParams, urlPostParams, externalSrcURL;
  bool isPostParamSet = false, isGetParamSet = false;

public:
  XSSFilter();

  void FetchRequestData(Document* aDocument);

  bool isInjected(nsCString reqParam, nsCString mScriptContent);

  bool isInjectedExternal(nsCString reqParam, nsCString externalScriptURI);

  bool isOnlyAlphaNumeric(nsCString reqParam);

  void TrimRequestData();

  bool StartFilterExternalScript(nsCOMPtr<nsIURI> scriptURI);

  bool StartFilterInternalScript(nsCString mScriptContent, ScriptLoadRequest* aRequest);
  
  bool StartFilterEventHandlerScript(const nsAString& handlerBody);

  bool FilterScriptExternal(nsCString reqParam, nsCOMPtr<nsIURI> scriptURI);

  bool FilterScriptInline(nsCString reqParam, nsCString mScriptContent);



  bool HasOpeningScriptTag(nsCString string, nsCString::const_iterator &iter);

  bool HasEventHandler(nsCString string, nsCString::const_iterator &iter);

  /**
   * @return the first occurrence of a character within a string buffer,
   *         or nullptr if not found
   */
  static const char *FindChar(char c, const char *begin, const char *end) {
  for (; begin < end; ++begin) {
    if (*begin == c)
      return begin;
  }
  return nullptr;
  };

  bool HasDangerousSrcAttribute(nsCString string, nsCString::const_iterator &iter);

  /**
   * Get src content of request parameter, if any, to srcContent
   *
   * @param reqParam The request input parameter
   * @param srcContent Holder for potential src content
   * @param iter Iterator to start search from
   */
  bool GetDangerousSrcAttribute(nsCString reqParam, nsCString& srcContent, nsCString::const_iterator &iter);

  bool HasScriptContent(nsCString string, nsCString::const_iterator &iter);

  bool IsScriptContainedInResponse(nsCString reqParam, nsCString scriptContent, nsCString::const_iterator &iter);

  bool IsExternalScriptSrcContainedInResponse(nsCString reqParam, nsCString scriptSrc);

  URLParams GetGETData(nsIURI* aURI);
  nsresult GetPOSTData();

  bool hasRequestData = false;

  bool filterStatus = false;

};


}; // namespace dom
}; // namespace mozilla

#endif // mozilla_dom_XSSFilter_h
