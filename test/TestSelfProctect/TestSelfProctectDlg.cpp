
// TestSelfProctectDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "TestSelfProctect.h"
#include "TestSelfProctectDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CTestSelfProctectDlg 对话框




CTestSelfProctectDlg::CTestSelfProctectDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CTestSelfProctectDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CTestSelfProctectDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CTestSelfProctectDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(SET_TRUST_PID, &CTestSelfProctectDlg::OnBnClickedTrustPid)
	ON_BN_CLICKED(SET_FILE_PATH, &CTestSelfProctectDlg::OnBnClickedFilePath)
	ON_BN_CLICKED(SET_REG_PATH, &CTestSelfProctectDlg::OnBnClickedRegPath)
	ON_BN_CLICKED(SET_PID_PROTECT_ON, &CTestSelfProctectDlg::OnBnClickedPidProtectOn)
	ON_BN_CLICKED(SET_PID_PROTECT_OFF, &CTestSelfProctectDlg::OnBnClickedPidProtectOff)
	ON_BN_CLICKED(SET_FILE_PROTECT_ON, &CTestSelfProctectDlg::OnBnClickedFileProtectOn)
	ON_BN_CLICKED(SET_FILE_PROTECT_OFF, &CTestSelfProctectDlg::OnBnClickedFileProtectOff)
	ON_BN_CLICKED(SET_REG_PROTECT_ON, &CTestSelfProctectDlg::OnBnClickedRegProtectOn)
	//ON_BN_CLICKED(UNINSTALL_DRV, &CTestSelfProctectDlg::OnBnClickedDrv)
	//ON_BN_CLICKED(UNINSTALL_DRIVER, &CTestSelfProctectDlg::OnBnClickedDriver)
	ON_BN_CLICKED(ID_INSTALL_DRIVER, &CTestSelfProctectDlg::OnBnClickedInstallDriver)
	ON_BN_CLICKED(ID_UNINSTALL_DRIVER, &CTestSelfProctectDlg::OnBnClickedUninstallDriver)
	ON_BN_CLICKED(SET_REG_PROTECT_OFF, &CTestSelfProctectDlg::OnBnClickedRegProtectOff)
END_MESSAGE_MAP()


// CTestSelfProctectDlg 消息处理程序

BOOL CTestSelfProctectDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CTestSelfProctectDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CTestSelfProctectDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CTestSelfProctectDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


#include "DriverInterface.h"
#include <vector>

typedef std::vector <PROTECT_PATH_NODE>	Path_Node_Vector;
typedef std::vector <DWORD>	Trust_Pid_Vector;

Trust_Pid_Vector gPidVector;
Path_Node_Vector gFileVector;
Path_Node_Vector gRegVector;

BOOL SetProctFilePath(Path_Node_Vector& FilePathVector)
{
	BOOL bRet = FALSE;
	size_t Counts = FilePathVector.size();
	if (Counts==0)
	{
		return bRet;
	}

	PATH_LIST FilePathList;
	memset(&FilePathList,0,sizeof(PATH_LIST));
	FilePathList.PathNum = Counts;
	for (int i=0;i<Counts;i++)
	{
		memcpy(&FilePathList.PathArray[i],&FilePathVector[i],sizeof(PROTECT_PATH_NODE));
	}

	bRet = SetProctFilePath(&FilePathList,sizeof(PATH_LIST));

	return bRet;
}

BOOL SetProctRegPath(Path_Node_Vector& RegPathVector)
{
	BOOL bRet = FALSE;
	size_t Counts = RegPathVector.size();
	if (Counts==0)
	{
		return bRet;
	}

	PATH_LIST RegPathList;
	memset(&RegPathList,0,sizeof(PATH_LIST));
	RegPathList.PathNum = Counts;
	for (int i=0;i<Counts;i++)
	{
		memcpy(&RegPathList.PathArray[i],&RegPathVector[i],sizeof(PROTECT_PATH_NODE));
	}

	bRet = SetProctRegPath(&RegPathList,sizeof(PATH_LIST));

	return bRet;
}

BOOL SetTrustPid(Trust_Pid_Vector& TrustPidVector)
{
	BOOL bRet = FALSE;
	size_t Counts = TrustPidVector.size();
	if (Counts==0)
	{
		return bRet;
	}

	PROCESS_WHITE_LIST TrustPidList;
	memset(&TrustPidList,0,sizeof(PROCESS_WHITE_LIST));
	TrustPidList.WhiteProcessNum = Counts;
	for (int i=0;i<Counts;i++)
	{
		TrustPidList.PidArray[i]=TrustPidVector[i];
	}

	bRet = SetTrustPid(&TrustPidList,sizeof(PROCESS_WHITE_LIST));

	return bRet;
}
void CTestSelfProctectDlg::OnBnClickedTrustPid()
{
	// TODO: Add your control notification handler code here
	CString strPid_1;
	CString strPid_2;
	GetDlgItem(PID_1)->GetWindowText(strPid_1);
	GetDlgItem(PID_2)->GetWindowText(strPid_2);
	gPidVector.push_back(_wtoi(strPid_1.GetBuffer()));
	gPidVector.push_back(_wtoi(strPid_2.GetBuffer()));
	BOOL bRet = SetTrustPid(gPidVector);
	if (bRet)
	{
		AfxMessageBox(_T("Set trust pid sucess!!"));
	}
	else
	{
		AfxMessageBox(_T("Set trust pid faid!!!!"));
	}
}


void CTestSelfProctectDlg::OnBnClickedFilePath()
{
	// TODO: Add your control notification handler code here
	gFileVector.clear();
	CString strFilePath_1;
	CString strFilePath_2;
	GetDlgItem(FILE_PATH1)->GetWindowText(strFilePath_1);
	GetDlgItem(FILE_PATH2)->GetWindowText(strFilePath_2);
	PROTECT_PATH_NODE PathNode;
	//
	memset(&PathNode,0,sizeof(PROTECT_PATH_NODE));
	PathNode.Access = 0;
	PathNode.PathLeng = strFilePath_1.GetLength()*sizeof(TCHAR);
	if (PathNode.PathLeng > MAX_PATH_LENGTH)
	{
		AfxMessageBox(_T("Error: file path too leng!!!!"));
		gFileVector.clear();
		return;
	}
	memcpy(PathNode.Path,strFilePath_1.GetBuffer(),PathNode.PathLeng);
	gFileVector.push_back(PathNode);

	//
	memset(&PathNode,0,sizeof(PROTECT_PATH_NODE));
	PathNode.Access = 0;
	PathNode.PathLeng = strFilePath_2.GetLength()*sizeof(TCHAR);
	if (PathNode.PathLeng > MAX_PATH_LENGTH)
	{
		AfxMessageBox(_T("Error: file path too leng!!!!"));
		gFileVector.clear();
		return;
	}
	memcpy(PathNode.Path,strFilePath_2.GetBuffer(),PathNode.PathLeng);
	gFileVector.push_back(PathNode);

	BOOL bRet = SetProctFilePath(gFileVector);
	if (bRet)
	{
		AfxMessageBox(_T("Set protect files sucess!!"));
	}
	else
	{
		AfxMessageBox(_T("Set protect files faid!!!!"));
	}
}


void CTestSelfProctectDlg::OnBnClickedRegPath()
{
	// TODO: Add your control notification handler code here
	gRegVector.clear();
	CString strRegPath_1;
	CString strRegPath_2;
	GetDlgItem(REG_PATH1)->GetWindowText(strRegPath_1);
	GetDlgItem(REG_PATH2)->GetWindowText(strRegPath_2);
	PROTECT_PATH_NODE PathNode;
	//
	memset(&PathNode,0,sizeof(PROTECT_PATH_NODE));
	PathNode.Access = 0;
	PathNode.PathLeng = strRegPath_1.GetLength()*sizeof(TCHAR);
	if (PathNode.PathLeng > MAX_PATH_LENGTH)
	{
		AfxMessageBox(_T("Error: file path too leng!!!!"));
		gRegVector.clear();
		return;
	}
	memcpy(PathNode.Path,strRegPath_1.GetBuffer(),PathNode.PathLeng);
	gRegVector.push_back(PathNode);

	//
	memset(&PathNode,0,sizeof(PROTECT_PATH_NODE));
	PathNode.Access = 0;
	PathNode.PathLeng = strRegPath_2.GetLength()*sizeof(TCHAR);
	if (PathNode.PathLeng > MAX_PATH_LENGTH)
	{
		AfxMessageBox(_T("Error: file path too leng!!!!"));
		gRegVector.clear();
		return;
	}
	memcpy(PathNode.Path,strRegPath_2.GetBuffer(),PathNode.PathLeng);
	gRegVector.push_back(PathNode);

	BOOL bRet = SetProctRegPath(gRegVector);
	if (bRet)
	{
		AfxMessageBox(_T("Set protect files sucess!!"));
	}
	else
	{
		AfxMessageBox(_T("Set protect files faid!!!!"));
	}
}


void CTestSelfProctectDlg::OnBnClickedPidProtectOn()
{
	// TODO: Add your control notification handler code here
	BOOL bRet = EnablePidProctect();
	if (bRet)
	{
		AfxMessageBox(_T("turn on pid protect sucess!!"));
	}
	else
	{
		AfxMessageBox(_T("turn on pid protect faild!"));
	}
}


void CTestSelfProctectDlg::OnBnClickedPidProtectOff()
{
	// TODO: Add your control notification handler code here
	BOOL bRet = DisablePidProctect();
	if (bRet)
	{
		AfxMessageBox(_T("turn off pid protect sucess!!"));
	}
	else
	{
		AfxMessageBox(_T("turn off pid protect faild!"));
	}
}


void CTestSelfProctectDlg::OnBnClickedFileProtectOn()
{
	// TODO: Add your control notification handler code here
	BOOL bRet = EnableFileProctect();
	if (bRet)
	{
		AfxMessageBox(_T("turn on file protect sucess!!"));
	}
	else
	{
		AfxMessageBox(_T("turn on file protect faild!"));
	}
}


void CTestSelfProctectDlg::OnBnClickedFileProtectOff()
{
	// TODO: Add your control notification handler code here
	BOOL bRet = DisableFileProctect();
	if (bRet)
	{
		AfxMessageBox(_T("turn off file protect sucess!!"));
	}
	else
	{
		AfxMessageBox(_T("turn off file protect faild!"));
	}
}


void CTestSelfProctectDlg::OnBnClickedRegProtectOn()
{
	// TODO: Add your control notification handler code here
	BOOL bRet = EnableRegProctect();
	if (bRet)
	{
		AfxMessageBox(_T("turn on reg protect sucess!!"));
	}
	else
	{
		AfxMessageBox(_T("turn on reg protect faild!"));
	}
}


void CTestSelfProctectDlg::OnBnClickedRegProtectOff()
{
	// TODO: Add your control notification handler code here
	BOOL bRet = DisableRegProctect();
	if (bRet)
	{
		AfxMessageBox(_T("turn off reg protect sucess!!"));
	}
	else
	{
		AfxMessageBox(_T("turn off reg protect faild!"));
	}
}

void CTestSelfProctectDlg::OnBnClickedInstallDriver()
{
	// TODO: Add your control notification handler code here
	BOOL bRet = InstallMiniFilerDriver();
	if (bRet) 
	{
		AfxMessageBox(_T("driver install sucess!!!"));
	}
	else
	{
		AfxMessageBox(_T("driver install faild!!!"));
	}
}

void CTestSelfProctectDlg::OnBnClickedUninstallDriver()
{
	// TODO: Add your control notification handler code here
	BOOL bRet = UnInstallMiniFilerDriver();
	if (bRet)
	{
		AfxMessageBox(_T("driver uninstall sucess!!!"));
	}
	else
	{
		AfxMessageBox(_T("driver uninstall faild!!!"));
	}
}


