// SPDX-License-Identifier: BSD-2-Clause-Patent

/*
 * Copyright 2025 Wangwei 
 * Copyright 2025 ISCAS Zhangtieyi <zhangtieyi@iscas.ac.cn>
 */
#include "shim.h"
#include "http.h"

EFI_HTTP_METHOD http_request_method;
CHAR8 *tx_body_json = NULL;

EFI_STATUS
print_device_path(EFI_HANDLE image_handle,
                  EFI_HANDLE http_binding_handle)
{
	EFI_STATUS efi_status;
	EFI_DEVICE_PATH_PROTOCOL *nic_device_path_protocol = NULL;
	efi_status = BS->OpenProtocol(http_binding_handle, &DevicePathProtocol,
	                              (void **)&nic_device_path_protocol,
	                              image_handle, NULL,
	                              EFI_OPEN_PROTOCOL_GET_PROTOCOL);
	if (EFI_ERROR(efi_status)) {
		perror(L"Failed to open nic device path protorol\n");
		return efi_status;
	}
	UINTN to_text_handle_count = 0;
	EFI_HANDLE *to_text_handles = NULL;
	efi_status =
		BS->LocateHandleBuffer(ByProtocol, &DevicePathToTextProtocol,
	                               NULL, &to_text_handle_count,
	                               &to_text_handles);
	if (EFI_ERROR(efi_status)) {
		perror(L"Failed to locate device path to text protorol\n");
		goto close_nic_protocol;
	}
	if (to_text_handle_count == 0) {
		efi_status = EFI_NOT_FOUND;
		goto free_handles;
	}
	EFI_DEVICE_PATH_TO_TEXT_PROTOCOL *device_path_to_text_protocol = NULL;
	efi_status =
		BS->OpenProtocol(to_text_handles[0], &DevicePathToTextProtocol,
	                         (void **)&device_path_to_text_protocol,
	                         image_handle, NULL,
	                         EFI_OPEN_PROTOCOL_GET_PROTOCOL);
	if (EFI_ERROR(efi_status)) {
		perror(L"Failed to open device path to text protorol\n");
		goto free_handles;
	}
	CHAR16 *text_device_path =
		device_path_to_text_protocol->ConvertDevicePathToText(
			nic_device_path_protocol,
			FALSE, // DisplayOnly: FALSE for full path, TRUE for abbreviated
			FALSE // AllowShortcuts: FALSE to disable shortcut expansion
		);
	if (text_device_path != NULL) {
		BS->FreePool(text_device_path);
	}
	BS->CloseProtocol(to_text_handles[0], &DevicePathToTextProtocol,
	                  image_handle, NULL);

free_handles:
	if (to_text_handles) {
		BS->FreePool(to_text_handles);
	}

close_nic_protocol:
	BS->CloseProtocol(http_binding_handle, &DevicePathProtocol,
	                  image_handle, NULL);
	return efi_status;
}

// Remember to free output outside if it's not null.
EFI_STATUS
ip4_cfg2_get_data(EFI_IP4_CONFIG2_PROTOCOL *ip4_cfg2_protocol,
                  EFI_IP4_CONFIG2_DATA_TYPE data_type, void **output)
{
	EFI_STATUS efi_status;
	UINTN get_size = 0;
	efi_status = ip4_cfg2_protocol->GetData(ip4_cfg2_protocol, data_type,
	                                        &get_size, NULL);
	if (efi_status != EFI_BUFFER_TOO_SMALL) {
		perror(L"Failed to get ip4 config2 data size\n");
		return efi_status;
	}
	efi_status = BS->AllocatePool(EfiBootServicesData, get_size, output);
	if (EFI_ERROR(efi_status)) {
		perror(L"Failed to allocate memory for data\n");
		return efi_status;
	}
	efi_status = ip4_cfg2_protocol->GetData(ip4_cfg2_protocol, data_type,
	                                        &get_size, *output);
	if (EFI_ERROR(efi_status)) {
		perror(L"Failed to get ip4 config2 data size\n");
		return efi_status;
	}
	return EFI_SUCCESS;
}

BOOLEAN
check_ip4_addr(EFI_IP4_CONFIG2_INTERFACE_INFO *ip4_cfg2_iface_info)
{
	return ip4_cfg2_iface_info->StationAddress.Addr[0] +
	               ip4_cfg2_iface_info->StationAddress.Addr[1] +
	               ip4_cfg2_iface_info->StationAddress.Addr[2] +
	               ip4_cfg2_iface_info->StationAddress.Addr[3] !=
	       0;
}

void
print_ip4_addr_verbose(EFI_IP4_CONFIG2_INTERFACE_INFO *ip4_cfg2_iface_info)
{
	console_print(L"Ip4 addr=%d.%d.%d.%d\n",
	              ip4_cfg2_iface_info->StationAddress.Addr[0],
	              ip4_cfg2_iface_info->StationAddress.Addr[1],
	              ip4_cfg2_iface_info->StationAddress.Addr[2],
	              ip4_cfg2_iface_info->StationAddress.Addr[3]);
}

// Remember to free output outside if it's not null.
EFI_STATUS
wait_until_get_iface_info(EFI_IP4_CONFIG2_PROTOCOL *ip4_cfg2_protocol,
                          EFI_IP4_CONFIG2_INTERFACE_INFO **p_ip4_cfg2_iface_info)
{
	EFI_STATUS efi_status;
	assert(p_ip4_cfg2_iface_info);
	if (*p_ip4_cfg2_iface_info) {
		BS->FreePool(*p_ip4_cfg2_iface_info);
		*p_ip4_cfg2_iface_info = NULL;
	}
	EFI_IP4_CONFIG2_INTERFACE_INFO *ip4_cfg2_iface_info = NULL;
	for (int i = 0; i < 30; i++) {
		console_print(L".");
		usleep(1000000000);
		efi_status = ip4_cfg2_get_data(ip4_cfg2_protocol,
		                               Ip4Config2DataTypeInterfaceInfo,
		                               (void **)&ip4_cfg2_iface_info);
		if (EFI_ERROR(efi_status)) {
			perror(L"Failed to open ip4 config2 protorol\n");
			return efi_status;
		}
		if (check_ip4_addr(ip4_cfg2_iface_info)) {
			print_ip4_addr_verbose(ip4_cfg2_iface_info);
			*p_ip4_cfg2_iface_info = ip4_cfg2_iface_info;
			break;
		}
		if (ip4_cfg2_iface_info) {
			BS->FreePool(ip4_cfg2_iface_info);
			ip4_cfg2_iface_info = NULL;
		}
	}
	if (*p_ip4_cfg2_iface_info) {
		return EFI_SUCCESS;
	} else {
		return EFI_NOT_READY;
	}
}


/*
 * connect_all_controllers - Connect all UEFI controllers recursively.
 *
 * In UEFI, when booting from disk, the BDS phase only connects the storage
 * path needed to load the boot option. Network device drivers
 * (VirtioPciDeviceDxe → VirtioNetDxe → MnpDxe → HttpDxe) are NOT connected
 * automatically unless a network boot option is present. This function
 * explicitly connects all controller handles so that the full network stack
 * (SNP → MNP → ARP → IP4 → TCP4 → HTTP) is initialised before we call
 * LocateHandleBuffer for EFI_HTTP_SERVICE_BINDING_PROTOCOL.
 *
 * NOTE: Driver initialization is asynchronous. After connection, we need to
 * wait for the drivers to complete initialization before querying protocols.
 */
static EFI_STATUS
connect_all_controllers(void)
{
	UINTN all_count = 0;
	EFI_HANDLE *all_handles = NULL;
	UINTN connected_count = 0;

	console_print(L"[HTTP] Connecting all UEFI controllers (may take time)...\n");

	EFI_STATUS st = BS->LocateHandleBuffer(AllHandles, NULL, NULL,
	                                       &all_count, &all_handles);
	if (EFI_ERROR(st) || !all_handles) {
		console_print(L"[HTTP] Failed to locate handles: %r\n", st);
		return st;
	}

	console_print(L"[HTTP] Found %lu controller handles\n", all_count);

	for (UINTN j = 0; j < all_count; j++) {
		EFI_STATUS connect_st = BS->ConnectController(all_handles[j], NULL, NULL, TRUE);
		if (!EFI_ERROR(connect_st)) {
			connected_count++;
		}
	}

	console_print(L"[HTTP] Connected %lu controllers\n", connected_count);
	BS->FreePool(all_handles);

	/* Give drivers time to initialize asynchronously */
	console_print(L"[HTTP] Waiting 2 seconds for driver initialization...\n");
	for (int i = 0; i < 20; i++) {
		console_print(L".");
		usleep(100000000);  /* 100ms */
	}
	console_print(L"\n");

	return EFI_SUCCESS;
}

/*
 * check_protocol_available - Check if a protocol is available on system
 */
static BOOLEAN
check_protocol_available(EFI_GUID *protocol_guid, const CHAR16 *protocol_name)
{
	UINTN count = 0;
	EFI_HANDLE *handles = NULL;
	EFI_STATUS st = BS->LocateHandleBuffer(ByProtocol, protocol_guid, NULL, &count, &handles);

	if (!EFI_ERROR(st) && count > 0) {
		console_print(L"[HTTP] ✓ Found %lu %s handles\n", count, protocol_name);
		if (handles)
			BS->FreePool(handles);
		return TRUE;
	} else {
		console_print(L"[HTTP] ✗ No %s handles found (status: %r)\n", protocol_name, st);
		return FALSE;
	}
}

EFI_STATUS
send_http_get_request(EFI_HANDLE image_handle, CHAR8 *uri)
{
	EFI_STATUS efi_status;

	console_print(L"\n[HTTP] ========== Starting HTTP Request ==========\n");
	console_print(L"[HTTP] URI: %a\n", uri);

	/*
	 * Ensure the network driver stack has been connected before we
	 * search for HTTP service binding handles. BDS only connects the
	 * storage path; the virtio-net PCI → SNP → MNP → HTTP chain needs
	 * an explicit ConnectController pass to become visible.
	 */
	efi_status = connect_all_controllers();
	if (EFI_ERROR(efi_status)) {
		console_print(L"[HTTP] Failed to connect controllers: %r\n", efi_status);
		return efi_status;
	}

	/* ---- Verify network stack layer by layer ---- */
	console_print(L"\n[HTTP] Checking network protocol stack:\n");
	
	/* Check HTTP Service Binding */
	check_protocol_available(&EFI_HTTP_BINDING_GUID, L"HTTP");

	/* ---- Now try to get HTTP binding handles ---- */
	console_print(L"\n[HTTP] Attempting to locate HTTP binding handles...\n");

	UINTN count = 0;
	EFI_HANDLE *http_binding_handles = NULL;
	efi_status = BS->LocateHandleBuffer(ByProtocol, &EFI_HTTP_BINDING_GUID,
	                                    NULL, &count, &http_binding_handles);
	if (EFI_ERROR(efi_status)) {
		console_print(L"[HTTP] ERROR: Failed to get HTTP binding handles (status: %r)\n", efi_status);
		console_print(L"[HTTP] This likely means the HTTP DXE driver was not loaded/connected.\n");
		console_print(L"[HTTP] RISC-V UEFI stack may differ from x86. Check firmware logs with:\n");
		console_print(L"[HTTP]   qemu -d all,guest_errors 2>&1 | grep -i http\n");
		perror(L"Failed to get http binding handles\n");
		return efi_status;
	}
	if (!count || !http_binding_handles) {
		console_print(L"[HTTP] ERROR: HTTP handles found but count=0\n");
		return EFI_NOT_FOUND;
	}

	console_print(L"[HTTP] ✓ Found %lu HTTP binding handle(s)\n", count);

	for (UINTN i = 0; i < count; i++) {
		console_print(L"[HTTP] ---- Processing HTTP handle %lu/%lu ----\n", i+1, count);
		
		/* print_device_path is debug-only; HTTP service binding handles
		 * are child handles without DevicePath, so failure is expected.
		 * Do NOT abort on error. */
		print_device_path(image_handle, http_binding_handles[i]);
		
		EFI_IP4_CONFIG2_PROTOCOL *ip4_cfg2_protocol = NULL;
		efi_status = BS->OpenProtocol(http_binding_handles[i],
		                              &EFI_IP4_CONFIG2_GUID,
		                              (void **)&ip4_cfg2_protocol,
		                              image_handle, NULL,
		                              EFI_OPEN_PROTOCOL_GET_PROTOCOL);
		if (EFI_ERROR(efi_status)) {
			console_print(L"[HTTP] Warning: Failed to open IP4 Config2 (status: %r)\n", efi_status);
			perror(L"Failed to open ip4 config2 protorol\n");
			goto break_loop;
		}
		
		EFI_IP4_CONFIG2_INTERFACE_INFO *ip4_cfg2_iface_info = NULL;
		efi_status = ip4_cfg2_get_data(ip4_cfg2_protocol,
		                               Ip4Config2DataTypeInterfaceInfo,
		                               (void **)&ip4_cfg2_iface_info);
		if (EFI_ERROR(efi_status)) {
			console_print(L"[HTTP] Failed to get IP4 config2 data (status: %r)\n", efi_status);
			perror(L"Failed to open ip4 config2 protorol\n");
			goto break_loop;
		}
		if (!ip4_cfg2_iface_info) {
			console_print(L"[HTTP] Failed to allocate IP4 config2 info structure\n");
			perror(L"Failed to get ip4 config2 info\n");
			goto break_loop;
		}
		if (check_ip4_addr(ip4_cfg2_iface_info)) {
			print_ip4_addr_verbose(ip4_cfg2_iface_info);
		} else {
			console_print(L"[HTTP] No IP address assigned, configuring DHCP...\n");
			efi_status = ip4_cfg2_protocol->SetData(
				ip4_cfg2_protocol, Ip4Config2DataTypePolicy,
				sizeof(EFI_IP4_CONFIG2_POLICY),
				&(EFI_IP4_CONFIG2_POLICY){
					Ip4Config2PolicyDhcp });
			if (EFI_ERROR(efi_status)) {
				console_print(L"[HTTP] Failed to set DHCP policy (status: %r)\n", efi_status);
				perror(L"Failed to set DHCP policy\n");
				goto break_loop;
			}
			// Loop until get ip.
			console_print(L"[HTTP] Waiting for DHCP to assign IP address...\n");
			efi_status = wait_until_get_iface_info(
				ip4_cfg2_protocol, &ip4_cfg2_iface_info);
			if (EFI_ERROR(efi_status)) {
				console_print(L"[HTTP] Failed to get IP via DHCP (status: %r)\n", efi_status);
				perror(L"Failed to get ip4 addr by DHCP\n");
				goto break_loop;
			}
		}
		
		console_print(L"[HTTP] Sending HTTP request to: %a\n", uri);
		void *data = NULL;
        // seems auto append.
		UINT64 datasize = 0;
		efi_status = httpboot_fetch_buffer_uri(image_handle,
		                                       http_binding_handles[i],
		                                       uri, &data, &datasize);
		if (EFI_ERROR(efi_status)) {
			console_print(L"[HTTP] ERROR: Failed to fetch from HTTP (status: %r)\n", efi_status);
			perror(L"Failed to fetch image: %r\n", efi_status);
			goto break_loop;
		}
		
		console_print(L"[HTTP] ✓ HTTP request succeeded, received %llu bytes\n", datasize);
		
	if (data && datasize > 0) {
		CHAR8 *safe_str = AllocatePool(datasize + 1);
		if (safe_str) {
			CopyMem(safe_str, data, datasize);
			safe_str[datasize] = '\0';
			console_print(L"Get http response body:%a\n", safe_str);
			FreePool(safe_str);
		}
	}

    if(data){
        BS->FreePool(data);
    }

break_loop:
		if (ip4_cfg2_iface_info) {
			BS->FreePool(ip4_cfg2_iface_info);
		}
		BS->CloseProtocol(http_binding_handles[i],
		                  &EFI_IP4_CONFIG2_GUID, image_handle, NULL);
		if (EFI_ERROR(efi_status)) {
			break;
		}
	}
reclaim:
	if (http_binding_handles) {
		BS->FreePool(http_binding_handles);
	}
	console_print(L"[HTTP] ========== HTTP Request Complete ==========\n\n");
	return efi_status;
}



// EFI_STATUS
// efi_main(EFI_HANDLE image_handle, EFI_SYSTEM_TABLE * systab){
//     EFI_STATUS efi_status;

//     InitializeLib(image_handle, systab);
//     console_print(L"Enter efi_main\n");

//     // `python3 -m http.server 8888` on isrc server
// 	// http_request_method = HttpMethodGet;	
// 	// CHAR8 uri[] = "http://10.20.173.8:8888/";
	
//     CHAR8 uri[] = "http://10.20.173.8:80/v1/keypair";    
// 	http_request_method = HttpMethodPost;
// 	tx_body_json="{\"algo\":\"sm2\",\"kms\":\"\",\"flow\":\"classic\"}";	

//     efi_status = send_http_get_request(image_handle, uri);
//     if (EFI_ERROR(efi_status)) {
//         perror(L"Failed to send http get request\n");
//         goto exit_main;
//     }

// exit_main:
//     return efi_status;
// }
