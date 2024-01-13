#include <windows.h>

#define ID_CHANGE_TEXT_BUTTON 1
#define SUCCESS 0

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    HWND hEdit = NULL;
    //__declspec(align(8)) static char buffer[256];
    static char buffer[512];
    switch (uMsg) {
        case WM_CREATE: {
            // Getting the main window dimensions
            RECT rc;
            GetClientRect(hwnd, &rc);
            int width = rc.right - rc.left;
            int height = rc.bottom - rc.top;

            // Center the Edit control
            int editWidth = 180;
            int editHeight = 25;
            int editX = (width - editWidth) / 2;
            int editY = (height - editHeight) * 2 / 5;  // Positioning a bit above the center

            hEdit = CreateWindowW(
                L"EDIT",
                L"Original Text",
                WS_CHILD | WS_VISIBLE | WS_BORDER,
                editX, editY, editWidth, editHeight,
                hwnd, NULL, GetModuleHandle(NULL), NULL);


            // Center the Button control below the Edit control
            int btnWidth = 180;
            int btnHeight = 25;
            int btnX = (width - btnWidth) / 2;
            int btnY = editY + editHeight + 10;

            CreateWindowW(
                L"BUTTON",
                L"Change Text",
                WS_CHILD | WS_VISIBLE,
                btnX, btnY, btnWidth, btnHeight,
                hwnd, (HMENU)ID_CHANGE_TEXT_BUTTON, GetModuleHandle(NULL), NULL);
            return SUCCESS;
        }

        case WM_COMMAND: {
            if (LOWORD(wParam) == ID_CHANGE_TEXT_BUTTON) {
                SendMessageW(hEdit, WM_SETTEXT, 0, (LPARAM)L"Updated SendMessageW!");
            }
            return SUCCESS;
        }
        case WM_COPYDATA: {
          PCOPYDATASTRUCT pCDS = (PCOPYDATASTRUCT) lParam;
          if (pCDS) {
             memcpy(buffer, pCDS->lpData, pCDS->cbData);
             //MessageBoxW(hwnd, (LPCWSTR)pCDS->lpData, L"Received Data", MB_OK);
          }
          return TRUE; // Data was processed
        }

        case WM_CLOSE: {
            PostQuitMessage(0);
            return SUCCESS;
        }

        default:
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
}

int WINAPI wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR lpCmdLine, _In_ int nCmdShow) {
    const wchar_t CLASS_NAME[] = L"SendMsgWindowClass";

    WNDCLASS wc = {0};

    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;

    RegisterClass(&wc);

    // Get the screen dimensions
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    // Define the window dimensions
    int windowWidth = 330;
    int windowHeight = 200;

    // Calculate the position to center the window
    int windowX = (screenWidth - windowWidth) / 2;
    int windowY = (screenHeight - windowHeight) / 2;

    //buffer = (char*)_aligned_malloc(512, 16);

    HWND hwnd = CreateWindowExW(
        0,                              // Optional window styles.
        CLASS_NAME,                     // Window class
        L"SendMessageW Example",        // Window text
        WS_OVERLAPPEDWINDOW,            // Window style

        // Size and position
        windowX, windowY, windowWidth, windowHeight,

        NULL,       // Parent window
        NULL,       // Menu
        hInstance,  // Instance handle
        NULL        // Additional application data
    );

    if (hwnd == NULL) {
        return 0;
    }

    ShowWindow(hwnd, nCmdShow);

    MSG msg = {0};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return 0;
}