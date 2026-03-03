#ifndef HTTP_REQUEST_H
#define HTTP_REQUEST_H

#include "shim.h"
#include <http.h>


EFI_STATUS
send_http_get_request(EFI_HANDLE image_handle, CHAR8 *uri);


// send_http_get_request(EFI_HANDLE image_handle, CHAR8 *uri,
// 					  VOID **response, UINT64 *response_size);

extern EFI_HTTP_METHOD http_request_method;
extern CHAR8 *tx_body_json;

#endif /* HTTP_REQUEST_H */