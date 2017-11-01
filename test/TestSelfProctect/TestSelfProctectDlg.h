
// TestSelfProctectDlg.h : ͷ�ļ�
//

#pragma once


// CTestSelfProctectDlg �Ի���
class CTestSelfProctectDlg : public CDialogEx
{
// ����
public:
	CTestSelfProctectDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
	enum { IDD = IDD_TESTSELFPROCTECT_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedTrustPid();
	afx_msg void OnBnClickedFilePath();
	afx_msg void OnBnClickedRegPath();
	afx_msg void OnBnClickedPidProtectOn();
	afx_msg void OnBnClickedPidProtectOff();
	afx_msg void OnBnClickedFileProtectOn();
	afx_msg void OnBnClickedFileProtectOff();
	afx_msg void OnBnClickedRegProtectOn();
	afx_msg void OnBnClickedDrv();
	afx_msg void OnBnClickedDriver();
	afx_msg void OnBnClickedInstallDriver();
	afx_msg void OnBnClickedUninstallDriver();
	afx_msg void OnBnClickedRegProtectOff();
	afx_msg void OnBnClickedButtonCallback();
	afx_msg void OnBnClickedButtonCallbackClose();
};
