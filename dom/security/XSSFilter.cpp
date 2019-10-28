/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*-  */
/*  vim: set ts=8 sts=2 et sw=2 tw=80: */
/*  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.   */

#include "XSSFilter.h"
#include "nsIMultiPartChannel.h"
#include<iostream>

#include <map>
#include <iterator>

namespace mozilla {
namespace dom {
  static nsresult GetHttpChannelHelper(nsIChannel* aChannel,
                                     nsIHttpChannel** aHttpChannel) {
  nsCOMPtr<nsIHttpChannel> httpChannel = do_QueryInterface(aChannel);
  if (httpChannel) {
    httpChannel.forget(aHttpChannel);
    return NS_OK;
  }

  nsCOMPtr<nsIMultiPartChannel> multipart = do_QueryInterface(aChannel);
  if (!multipart) {
    *aHttpChannel = nullptr;
    return NS_OK;
  }

  nsCOMPtr<nsIChannel> baseChannel;
  nsresult rv = multipart->GetBaseChannel(getter_AddRefs(baseChannel));
  if (NS_WARN_IF(NS_FAILED(rv))) {
    return rv;
  }

  httpChannel = do_QueryInterface(baseChannel);
  httpChannel.forget(aHttpChannel);

  return NS_OK;
}
nsCString
getRidOfNonAscii(nsCString mScriptContent){

  // loop through all chars in reqParam
  const char *start = mScriptContent.BeginReading();
  const char *end = mScriptContent.EndReading();
  int i = 0;
  for (; start < end; ++start) {
    if ( (*start < '0') || (*start > '9' && *start < 'A') || (*start > 'Z' && *start < '_')
      || (*start > '_' && *start < 'a') ||(*start > 'z')) {
      mScriptContent.Truncate(i);
      start = end;
    }
    i++;
  }
   return mScriptContent;
}

XSSFilter::XSSFilter()
{

}

void
XSSFilter::FetchRequestData(Document *aDocument) {
  if (aDocument) {
    mDocument = aDocument;
    GetPOSTData();
    //GetGETData();
    TrimRequestData();
  }
}

bool
XSSFilter::isInjected(nsCString reqParam, nsCString mScriptContent) {
  std::cout << mScriptContent.get();
  mScriptContent = getRidOfNonAscii(mScriptContent);
  nsContentUtils::ASCIIToLower(reqParam);
  printf(" Param: %s \n compared with \n %s \n", reqParam.get(), mScriptContent.get());
  nsContentUtils::ASCIIToLower(mScriptContent);
  printf(" Param: %s \n compared with \n %s \n", reqParam.get(), mScriptContent.get());

  if (FindInReadable(mScriptContent, reqParam)) {
    return true;
  }
  return false;
}

bool
XSSFilter::isInjectedExternal(nsCString reqParam, nsCString externalScriptURI) {
  nsContentUtils::ASCIIToLower(reqParam);
  nsContentUtils::ASCIIToLower(externalScriptURI);
  //printf("\n External: Param: %s \n compared with \n %s", reqParam.get(), externalScriptURI.get());
  if (FindInReadable(externalScriptURI, reqParam)) {
    return true;
  }
  return false;
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

void
XSSFilter::TrimRequestData() {

  nsString value, key;
  if(isPostParamSet){
    for (uint32_t i = 0; i < urlPostParams.Length(); i++) {
      value = urlPostParams.GetValueAtIndex(i);
      key = urlPostParams.GetKeyAtIndex(i);
      // if only alphanumeric contents, then remove parameter, as it does not contain any suspicious data
      if (isOnlyAlphaNumeric(NS_ConvertUTF16toUTF8(value))) {
        urlPostParams.Delete(key);
      }
    }
  }
  for (uint32_t i = 0; i < urlGetParams.Length(); i++) {
    value = urlGetParams.GetValueAtIndex(i);
    key = urlGetParams.GetKeyAtIndex(i);
    // if only alphanumeric contents, then remove parameter, as it does not contain any suspicious data
    if (isOnlyAlphaNumeric(NS_ConvertUTF16toUTF8(value))) {
      urlGetParams.Delete(key);
    }
  }

}

bool
XSSFilter::StartFilterExternalScript(nsCOMPtr<nsIURI> scriptURI) {
  uint32_t paramLength = urlPostParams.Length();
  nsString paramName, paramValue;
  nsCString externalScriptURI;

  // Check all POST parameters
  for (uint32_t i = 0; i < paramLength; i++) {
    paramName = urlPostParams.GetKeyAtIndex(i);
    paramValue = urlPostParams.GetValueAtIndex(i);

    nsCString reqParam = NS_ConvertUTF16toUTF8(paramValue);
    scriptURI->GetSpec(externalScriptURI);

    if (isInjectedExternal(reqParam, externalScriptURI)) {
      printf("\n Script URI: %s", externalScriptURI.get());
      printf("\n ----- Script blocked by XSS filter ----- \n");
      return false;
    }
  }

  paramLength = urlGetParams.Length();

  // Check all GET parameters
  for (uint32_t i = 0; i < paramLength; i++) {
    paramName = urlGetParams.GetKeyAtIndex(i);
    paramValue = urlGetParams.GetValueAtIndex(i);

    nsCString reqParam = NS_ConvertUTF16toUTF8(paramValue);
    scriptURI->GetSpec(externalScriptURI);

    if (isInjectedExternal(reqParam, externalScriptURI)) {
      printf("\n Script URI: %s", externalScriptURI.get());
      printf("\n ----- Script blocked by XSS filter ----- \n");
      return false;
    }
  }

  return true;
}

bool
XSSFilter::StartFilterInternalScript(nsCString script, ScriptLoadRequest* aRequest){
    printf("filtering! StartFilterInternalScript 1 \n");
  nsIURI* aURI = aRequest->mURI;
    if (aURI) {
      nsAutoCString URL;
      nsresult rv = aURI->GetPathQueryRef(URL);
      if(rv == NS_OK){
        return StartFilterInternalScript(script, URL);
      }
    }
  return true;
}

bool
XSSFilter::StartFilterInternalScript(nsCString script, nsCString url) {
  uint32_t paramLength = urlPostParams.Length();
  nsString paramName, paramValue;
  printf("filtering! StartFilterInternalScript 2\n");
  printf("script: %s \n",script.get());
  printf("url: %s \n", url.get());
  // Check all POST parameters
  for (uint32_t i = 0; i < paramLength; i++) {
    paramName = urlPostParams.GetKeyAtIndex(i);
    paramValue = urlPostParams.GetValueAtIndex(i);

    nsCString reqParam = NS_ConvertUTF16toUTF8(paramValue);

    if (isInjected(reqParam, script)) {
      printf("\n Script: %s", script.get());
      printf("\n ----- Script blocked by XSS filter ----- \n");
      return false;
    }
  }
  URLParams params = GetGETData(url);
  paramLength = params.Length();

  // Check all GET parameters
  for (uint32_t i = 0; i < paramLength; i++) {
    paramName = params.GetKeyAtIndex(i);
    paramValue = params.GetValueAtIndex(i);

    nsCString reqParam = NS_ConvertUTF16toUTF8(paramValue);

    if (isInjected(reqParam, script)) {
      printf("\n Script: %s", script.get());
      printf("\n ----- Script blocked by XSS filter ----- \n");
      return false;
    }
  }

  return true;
}

bool
XSSFilter::StartFilterEventHandlerScript(const nsAString& handlerBody) {
  nsCString mScriptContent = NS_ConvertUTF16toUTF8(handlerBody);

  uint32_t paramLength = urlPostParams.Length();
  nsString paramName, paramValue;

  // Check all POST parameters
  for (uint32_t i = 0; i < paramLength; i++) {
    paramName = urlPostParams.GetKeyAtIndex(i);
    paramValue = urlPostParams.GetValueAtIndex(i);

    nsCString reqParam = NS_ConvertUTF16toUTF8(paramValue);

    if (isInjected(reqParam, mScriptContent)) {
      printf("\n Script: %s", mScriptContent.get());
      printf("\n ----- Script blocked by XSS filter ----- \n");
      return false;
    }
  }
  paramLength = urlGetParams.Length();

  // Check all GET parameters
  for (uint32_t i = 0; i < paramLength; i++) {
    paramName = urlGetParams.GetKeyAtIndex(i);
    paramValue = urlGetParams.GetValueAtIndex(i);

    nsCString reqParam = NS_ConvertUTF16toUTF8(paramValue);

    if (isInjected(reqParam, mScriptContent)) {
      printf("\n Script: %s", mScriptContent.get());
      printf("\n ----- Script blocked by XSS filter ----- \n");
      return false;
    }
  }
  return true;
}



nsresult
XSSFilter::GetPOSTData(){
  nsresult rv;
  if (!mDocument) {
    return NS_OK;
  }
  nsIChannel *mChannel = (mDocument->GetChannel());
  nsCOMPtr<nsIUploadChannel> mUploadChannel;
  if (!mChannel) {
     return NS_OK;
  }
  nsCOMPtr<nsIHttpChannel> mHttpChannel(do_QueryInterface(mChannel));
  rv = GetHttpChannelHelper(mChannel, getter_AddRefs(mHttpChannel));
  if(!mHttpChannel){
    return NS_OK;
  }
  mUploadChannel = do_QueryInterface(mHttpChannel);
  if(!mUploadChannel){
    return NS_OK;
  }
  // Get request body stream
  nsCOMPtr<nsIInputStream> mBodyStream;
  mUploadChannel->GetUploadStream(getter_AddRefs(mBodyStream));

  if (!mBodyStream) {
      return NS_OK;
  }
  // seekable stream
  nsCOMPtr<nsISeekableStream> postDataSeekable = do_QueryInterface(mBodyStream);
  nsresult rvSeek;
  if (postDataSeekable) {
   rvSeek = postDataSeekable->Seek(nsISeekableStream::NS_SEEK_SET, 0);
  }

  uint64_t mAvailableData = 0;
  rv = mBodyStream->Available(&mAvailableData);
  if (NS_SUCCEEDED(rv) && mAvailableData == 0) {
    // EOF
  }
  if(NS_FAILED(rv)) {
    printf("\n NS_FAILED(rv)");
  }

  if (mAvailableData > 0) {
    nsresult mRv;
    uint32_t numRead, totalRead = 0;
    // buf size is random, since mAvailableData always is 0
    char buf[mAvailableData];

    while (1) {
      mRv = mBodyStream->Read(buf, sizeof(buf), &numRead);
      if (totalRead == 0) {
      totalRead = numRead;
      }
      if (NS_FAILED(mRv)) {
        printf("### error reading stream: %x\n", mRv);
        break;
      }
      if (numRead == 0) {
        break;
      }
    }

    nsCString mBufferContent(buf, totalRead);
    urlPostParams.ParseInput(mBufferContent);

    //printf("\n2. Request data (buffer): %s\n", mBufferContent.get());
    isPostParamSet = true;
    return NS_OK;
    }
}// end POST data


URLParams
XSSFilter::GetGETData(nsCString URL) {
  URLParams params;
  // Get URL search params (GET)
  if(mDocument) {
    int32_t queryBegins = URL.FindChar('?');
    if(queryBegins < 0){
        queryBegins = URL.FindChar(':');
    }
    if (queryBegins > 0) {
        params.ParseInput(Substring(URL, queryBegins + 1));
      }
    }
  return params;
  }

/***************************
*** LESS RELEVANT CODE: ***
***************************/

bool
XSSFilter::FilterScriptExternal(nsCString reqParam, nsCOMPtr<nsIURI> scriptURI) {

  nsCString::const_iterator iter;
  nsCString externalScriptURI;
  scriptURI->GetSpec(externalScriptURI);

  if (HasEventHandler(reqParam, iter)) {
    printf("\nHas event handler!!!\n");
  }

  // if have opening script tag '<script' and content inside 'src' tag -> UNSAFE if found in response
  if (HasOpeningScriptTag(reqParam, iter)) {
    if (GetDangerousSrcAttribute(reqParam, srcFromRequest, iter)) {
      // printf("\n external scr content: %s", externalScriptURI.get());
      if (IsExternalScriptSrcContainedInResponse(srcFromRequest, externalScriptURI)) {
        printf("\n Script URI: %s", externalScriptURI.get());
        printf("\n ----- Script blocked by XSS filter ----- \n");
        return false;
      }
    } else {
      // printf("\nexternal %s: have no src attribute content",
      //        reqParam.get());
    }
  } else {
    // printf("\nContent DO NOT HAVE opening script tag\n");
  }

  return true;
}

bool
XSSFilter::FilterScriptInline(nsCString reqParam, nsCString mScriptContent) {

  nsCString::const_iterator iter;

  if(HasEventHandler(reqParam, iter)) {
    printf("\nHas event handler!!!\n");
  }

  // if contains opening script tag '<script' and there exists content after script closing tag '>': UNSAFE if found in response
  if (HasOpeningScriptTag(reqParam, iter)) {

    // we have '<script' then maybe something then we need to
    // find '>' before continuing
    if (HasScriptContent(reqParam, iter)) {

      // check if param is contained in response
      if (IsScriptContainedInResponse(reqParam, mScriptContent,
                                      iter)) {

        // param found in reponse, filter mark as unsafe
        printf("\n Script: %s", mScriptContent.get());
        printf("\n ----- Script blocked by XSS filter ----- \n");
        return false;
      } else {
        // request param is not contained in response
      }
    } else {
      // param does not have script content inside '<script' tag
    }

  } else {
    // param does not have opening script tag '<script'
  }

  return true;

}

bool
XSSFilter::HasOpeningScriptTag(nsCString string,
                                      nsCString::const_iterator &iter) {

  nsContentUtils::ASCIIToLower(string);
  // Tag
  NS_NAMED_LITERAL_CSTRING(openingScriptTag, "<script");

  nsString mInsideScript;
  // check for 'script' tag

  nsCString::const_iterator start, end;
  string.BeginReading(start);
  string.EndReading(end);

  if (FindInReadable(openingScriptTag, start, end)) {
    // 'end' now points to the first character after <script
    iter = end;
    return true;
  }
  return false;
}

bool
XSSFilter::XSSFilter::HasDangerousSrcAttribute(nsCString string,
                                            nsCString::const_iterator &iter) {

  NS_NAMED_LITERAL_CSTRING(srcAttribute, "src");

  nsContentUtils::ASCIIToLower(string);
  nsCString::const_iterator iStart, iEnd;
  iStart = iter;
  string.EndReading(iEnd);

  if (FindInReadable(srcAttribute, iStart, iEnd)) {

    // start points to first character after 'src'
    const char *start = iEnd.get();
    const char *end = string.EndReading();

    start = FindChar('=', start, end);

    // FIX: only spaces

    while (start) {
      ++start;

      if (start >= (end)) {
        return false;
      }

      // check if empty single quotes ELSE IF check if empty double quotes ELSE
      // IF if not space character, then it is not safe
      if (*start == '\'') {
        if (start[1] == '\'') {
          return false;
        }
      } else if (*start == '"') {
        if (start[1] == '"') {
          return false;
        }
      } else if (*start != ' ') {
        return true;
      }
    }
  }
  // safe by default...
  return false;
}

bool
XSSFilter::GetDangerousSrcAttribute(nsCString reqParam, nsCString& srcContent, nsCString::const_iterator &iter){

  NS_NAMED_LITERAL_CSTRING(srcAttribute, "src");
  NS_NAMED_LITERAL_CSTRING(equalSign, "=");
  NS_NAMED_LITERAL_CSTRING(closeTag, ">");

  nsContentUtils::ASCIIToLower(reqParam);
  nsCString::const_iterator iStart, iEnd, srcStart, quoteStart, quoteEnd;
  iStart = iter;
  reqParam.EndReading(iEnd);

  nsCString srcContentInternal;

  if (FindInReadable(srcAttribute, iStart, iEnd)) {
    //iEnd is next start
    iStart = iEnd;
    reqParam.EndReading(iEnd);

    if (FindInReadable(equalSign, iStart, iEnd)) {
      // save iEnd here, which will be the starting point for scrContent
      // After following code, iEnd will be the end, use substring
      srcStart = iEnd;
      iStart = iEnd;
      reqParam.EndReading(iEnd);

      if (FindInReadable(closeTag, iStart, iEnd)) {

        // found '>' after 'src=', use startSrcContent and iStart to substring
        srcContentInternal = Substring(srcStart, iStart);

        iEnd = iStart;
        quoteStart = srcStart;
        quoteEnd = iEnd;

        // find start quote
        if (FindInReadable(NS_LITERAL_CSTRING("\""), quoteStart, quoteEnd)) {
          srcStart = quoteEnd;
          // find end quote
          quoteStart = quoteEnd;
          quoteEnd = iEnd;
          if (FindInReadable(NS_LITERAL_CSTRING("\""), quoteStart, quoteEnd)) {
            srcContentInternal = Substring(srcStart, quoteStart);
          }
        } else if (FindInReadable(NS_LITERAL_CSTRING("'"), quoteStart = srcStart, quoteEnd = iEnd)) {
          srcStart = quoteEnd;
          // find end quote
          quoteStart = quoteEnd;
          quoteEnd = iEnd;
          if (FindInReadable(NS_LITERAL_CSTRING("'"), quoteStart, quoteEnd)) {
            srcContentInternal = Substring(srcStart, quoteStart);
          }
        }

        printf("\n Src content: %s", srcContentInternal.get());
        srcContent = srcContentInternal;
        return true;
      } else {

        srcContentInternal = Substring(srcStart, iEnd);

        quoteStart = srcStart;
        quoteEnd = iEnd;

        // find start quote
        if (FindInReadable(NS_LITERAL_CSTRING("\""), quoteStart, quoteEnd)) {
          srcStart = quoteEnd;
          // find end quote
          quoteStart = quoteEnd;
          quoteEnd = iEnd;
          if (FindInReadable(NS_LITERAL_CSTRING("\""), quoteStart, quoteEnd)) {
            srcContentInternal = Substring(srcStart, quoteStart);
          }
        } else if (FindInReadable(NS_LITERAL_CSTRING("'"), quoteStart = srcStart, quoteEnd = iEnd)) {
          srcStart = quoteEnd;
          // find end quote
          quoteStart = quoteEnd;
          quoteEnd = iEnd;
          if (FindInReadable(NS_LITERAL_CSTRING("'"), quoteStart, quoteEnd)) {
            srcContentInternal = Substring(srcStart, quoteStart);
          }
        }

        printf("\n Src content: %s", srcContentInternal.get());
        srcContent = srcContentInternal;
        return true;
      }
    }

  }
  // safe by default...
  return false;
}

bool
XSSFilter::HasScriptContent(nsCString string,
                                    nsCString::const_iterator &iter) {

  nsContentUtils::ASCIIToLower(string);
  const char *start = iter.get();
  const char *end = string.EndReading();

  // find end of opening script tag '<script'
  start = FindChar('>', start, end);

  while (start) {
    ++start;

    if (start >= (end)) {
      return false;
    }

    if (*start == '<') {
      if (start[1] == '/' && start[2] == 's' && start[3] == 'c' &&
          start[4] == 'r' && start[5] == 'i' && start[6] == 'p' &&
          start[7] == 't') {
        return false;
      }
    }

    if (*start != ' ') {
      return true;
    }

    return true;
  }
}

bool
XSSFilter::IsScriptContainedInResponse(
    nsCString reqParam, nsCString scriptContent,
    nsCString::const_iterator &iter) {

  // FIX input: <script>    alert("XSS")</script> does not get detected
  // <script>alert("XSS")</script> works fine

  NS_NAMED_LITERAL_CSTRING(closingTag, ">");
  NS_NAMED_LITERAL_CSTRING(closingScriptTag, "</script");

  nsContentUtils::ASCIIToLower(reqParam);
  nsContentUtils::ASCIIToLower(scriptContent);
  nsCString reqParamContent;

  // inline script
  // extract script content from reqParam
  // compare reqParam script content with scriptContent
  nsCString::const_iterator start, end, startContent, endContent;
  // iter should point to first char after '<script', if method
  // 'HasOpeningScriptTag' was called first
  start = iter;
  reqParam.EndReading(end);
  endContent = end;

  if (FindInReadable(closingTag, start, end)) {
    // start now contains '>'
    ++start;
    // set startContent to first char after '>'
    startContent = start;

    reqParam.EndReading(end);
    // if there is a closing script tag '</script'
    if (FindInReadable(closingScriptTag, start, end)) {
      // start now contains '<'
      reqParamContent.Assign((Substring(startContent, start)));
    } else {
      // no closing script tag, so assign reqParamContent to everything from the
      // '>' and outwards
      reqParamContent.Assign((Substring(startContent, endContent)));
    }

    // check if scriptContent contains reqParamContent
    scriptContent.BeginReading(start);
    scriptContent.EndReading(end);

    if (FindInReadable(reqParamContent, start, end)) {
      return true;
    }
  }

  return false;
}

bool
XSSFilter::IsExternalScriptSrcContainedInResponse(nsCString reqParam, nsCString scriptSrc) {

  nsContentUtils::ASCIIToLower(reqParam);

  printf("\nreqParam: %s, scriptSrc: %s", reqParam.get(), scriptSrc.get());

  // Currently checking both ways:
  // Workaround for extracting actual src from "" tags, '' tags or no tags
  if (FindInReadable(scriptSrc, reqParam)) {
    return true;
  } else if (FindInReadable(reqParam, scriptSrc)) {
    return true;
  }
  return false;
}


bool
XSSFilter::HasEventHandler(nsCString string, nsCString::const_iterator &iter) {

  nsContentUtils::ASCIIToLower(string);
  // Tag
  NS_NAMED_LITERAL_CSTRING(openingTag, "<");
  NS_NAMED_LITERAL_CSTRING(eventHandlerStart, "on");
  NS_NAMED_LITERAL_CSTRING(space, " ");

  nsCString::const_iterator iStart, iEnd;
  string.BeginReading(iStart);
  string.EndReading(iEnd);

  printf("\n1. starting looking for event handler\n");

  //if (FindInReadable(eventHandlerStart, iStart, iEnd)) {
  //  printf("\n0. Found 'on'!\n");
  //}

  // find '<' tag
  if (FindInReadable(openingTag, iStart, iEnd)) {
    printf("\n2. found '<' tag\n");

    // reposition iStart and iEnd
    iStart = iEnd;
    string.EndReading(iEnd);

    const char *start = iStart.get();
    const char *end = iEnd.get();

    // find at least one character following the '<' tag
    if (*start != ' ') { //*start == 'a' || *start == 'x' || *start == 'i') {
      printf("\n3. found char after '<' tag\n");
      // find at least one space character
      if (FindChar(' ', start, end)) {
      //if (FindInReadable(space, iStart, iEnd)) {
        printf("\n4. found space char\n");
        // find start of event handler: 'on'
        if (FindInReadable(eventHandlerStart, iStart, iEnd)) {
          printf("\n5. found 'on'\n");
          // find at least three characters that is not a space
          // start points to first character after 'on'
          const char *startOn = iEnd.get();

          if (*startOn != ' ' && startOn[1] != ' ' && startOn[2] != ' ' && *startOn != '/' && startOn[1] != '/' && startOn[2] != '/' && *startOn != '=' && startOn[1] != '=' && startOn[2] != '=') {
            printf("\n6. found at least 3 chars following 'on'\n");
            // eventhandler onxxx found, look for '>' tag
            if (FindChar('>', startOn + 3, end)) {
              printf("\n7. Finish, found '>' tag!\n");
              return true;
            }
          }

        }

      }

    }

  }
 return false;
}

} // namespace dom
} // namespace mozilla
