/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*-  */
/*  vim: set ts=8 sts=2 et sw=2 tw=80: */
/*  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.   */

#include "XSSFilter.h"

#include <map>
#include <iterator>

namespace mozilla {
namespace dom {

XSSFilter::XSSFilter()
{

}

bool
XSSFilter::StartFilter(const nsAString& script, ScriptLoadRequest* aRequest){
  printf("filtering! StartFilter 1 \n");
  nsIURI* aURI = aRequest->mURI;
    if (aURI) {
      nsAutoCString URL;
      nsresult rv = aURI->GetPathQueryRef(URL);
      if(rv == NS_OK){
        return StartFilter(script, NS_ConvertUTF8toUTF16(URL));
      }
    }
  return true;
}

bool
XSSFilter::StartFilter(const nsAString& script, const nsAString& url) {
  printf("filtering! StartFilter 2\n");
  //printf("script: %s \n",NS_ConvertUTF16toUTF8(script).get());
  //printf("url: %s \n", NS_ConvertUTF16toUTF8(url).get());
  URLParams params;
  nsString paramName, paramValue;
  nsCString reqParam;

  if(NS_SUCCEEDED(GetGETData(NS_ConvertUTF16toUTF8(url), params))){
    uint32_t paramLength = params.Length();
    // Check all GET parameters
    for (uint32_t i = 0; i < paramLength; i++) {
      paramName = params.GetKeyAtIndex(i);
      paramValue = params.GetValueAtIndex(i);
      printf("%s \n", NS_ConvertUTF16toUTF8(paramValue).get());

      if (isInjected(paramValue, script)) {
        printf("\n Script URI: %s", NS_ConvertUTF16toUTF8(script).get());
        printf("\n ----- Script blocked by XSS filter ----- \n");
        return false;
     }
  }
  }
  if (isInjected(url, script)) { // can we guarantee that all instances were caught by the above?
    printf("\n Script: %s", NS_ConvertUTF16toUTF8(script).get());
    printf("\n ----- Script blocked by XSS filter at complete url against script----- \n");
    return false;
  }
  return true;
}

bool
XSSFilter::StartFilter(nsCOMPtr<nsIURI> scriptURI) {
  printf("filtering! StartFilter 3\n");
  nsAutoCString externalScriptURI;
  scriptURI->GetSpec(externalScriptURI);
  printf("external script uri received = '%s'", externalScriptURI.get());
  return true;
}

bool
XSSFilter::isInjected(const nsAString& reqParam, const nsAString& mScriptContent) {
  // mScriptContent = getRidOfNonAscii(mScriptContent);
  //nsContentUtils::ASCIIToLower(reqParam);
  //nsContentUtils::ASCIIToLower(mScriptContent);
  printf("Script: '%s' compared with url attribute: '%s' \n", NS_ConvertUTF16toUTF8(mScriptContent).get(), NS_ConvertUTF16toUTF8(reqParam).get());
  if (FindInReadable(mScriptContent, reqParam)) {
    return true;
  }
  return false;
}

nsresult
XSSFilter::GetGETData(const nsACString& URL, URLParams& params) {
  //how do we identify the different types of input? Different flows seems the easy way out.
  // Get URL search params (GET)
  nsresult rv = NS_ERROR_BASE;
  int32_t queryBegins = URL.FindChar('?');
  if (queryBegins > 0) {
    params.ParseInput(Substring(URL, queryBegins + 1));
    rv = NS_OK;
  }
  TrimRequestData(params);
  if(params.Length() == 0){
    rv = NS_ERROR_BASE;
  }
  return rv;
}


void
XSSFilter::TrimRequestData(URLParams& params) {
  nsString value, key;
  for (uint32_t i = 0; i < params.Length(); i++) {
    value = params.GetValueAtIndex(i);
    key = params.GetKeyAtIndex(i);
    // if only alphanumeric contents, then remove parameter, as it does not contain any suspicious data
    if (isOnlyAlphaNumeric(NS_ConvertUTF16toUTF8(value))) {
      params.Delete(key);
    }
  }
}

bool
XSSFilter::isOnlyAlphaNumeric(nsCString reqParam) {

  // loop through all chars in reqParam
  const char *start = reqParam.BeginReading();
  const char *end = reqParam.EndReading();

  for (; start < end; ++start) {
    if ( (*start < '0') || (*start > '9' && *start < 'A') || (*start > 'Z' && *start < '_')
      || (*start > '_' && *start < 'a') ||(*start > 'z')) {
      return false;
    }
  }
  return true;
}

} // namespace dom
} // namespace mozilla
