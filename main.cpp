#include<bits/stdc++.h>
#include<windows.h>
using namespace std;
bool file(string name) {
	ifstream file(name.c_str());
	return !file.fail();
}//�鿴�ļ��Ƿ���� 
double slowed=30;
void slow_print(string s) {
	for(int i=0; i<s.length(); i++) {
		cout << s[i];
		Sleep(slowed);
	}
	puts("");
}
void ero(){
	slow_print("dev by ");
	cout << "\n\n\n\n" << endl;
	cout << "\t                                                            .o8"<< endl;
	cout << "\t                                                           \"888" << endl;
	cout << "\t  oooooooo  .ooooo.  oooo    ooo  .oooooooo  .ooooo.   .oooo888" << endl;
	cout << "\t d'\"\"7d8P  d88' `\"Y8  `88.  .8'  888' `88b  d88' `88b d88' `888" << endl;
	cout << "\t   .d8P'   888         `88..8'   888   888  888   888 888   888" << endl;
	cout << "\t d8888888P  `Y8bod8P'     .8'     `8oooooo.  `Y8bod8P' `Y8bod88 \"" << endl;
	cout << "\t                     .o..P'      d\"     YD                     " << endl;
	cout << "\t                     `Y8P'       \"Y88888P'                     \n\n" << endl;
	slow_print("\n\n"); 
	system("color 03");
	Sleep(2000);
	system("cls");
	system("color 07");
}

int main(){
	if(!file("Tongyi")){
		cout << "ʹ�ñ����ǰ������ͬ���û�����!" << endl;
		cout << "�����е��������https://zcygod.top/tiaokuan/�Բ鿴" << endl;
		cout << "��������Ļֻ����ʾһ��" << endl;
		cout << "\n\n\n��ѡ��[Y/N]:"<< endl;
		char choosepppp;
		cin >> choosepppp;
		if(choosepppp=='Y'){
			cout << "��ͬ��������" << endl; 
			system("echo > Tongyi");	
			system("cls");
		}else {
			cout << "���ܾ�������" << endl; 
			return 0;
		}
	}
	ero();
	cout << "ʹ��ǰ����ȷ��������ӵ�й���ԱȨ�ޣ�" << endl;
	cout << "ʹ��ǰ����ȷ��������ӵ�й���ԱȨ�ޣ�" << endl;
	cout << "ʹ��ǰ����ȷ��������ӵ�й���ԱȨ�ޣ�" << endl;
	cout << "ʹ��ǰ����ȷ��������ӵ�й���ԱȨ�ޣ�" << endl;
	cout << "ʹ��ǰ����ȷ��������ӵ�й���ԱȨ�ޣ�" << endl;
	cout << "ʹ��ǰ����ȷ��������ӵ�й���ԱȨ�ޣ�" << endl;
	cout << "ʹ��ǰ����ȷ��������ӵ�й���ԱȨ�ޣ�" << endl;
	cout << "ʹ��ǰ����ȷ��������ӵ�й���ԱȨ�ޣ�" << endl;
	
	Sleep(2000);
	system("copy /Y .\\lib\\*.* C:\\Windows");
	start:
	cout << "������Ҫִ�еĲ�����" << endl;
	cout << "\n1.�������򣨱����������棬��Ϊzcygodˮƽ���㣩" << endl;
	cout << "\n2.�Ҳ�֪��������" <<endl; 
	int choose;
	cin >> choose;
	if(choose==1){
		system("cls");
		cout << "��������Ҫ�����ĳ���Ľ������֣�Ӣ����������������£��ȸ������chrome.exe,edge�������msedge.exe" << endl;
		string name;
		cin >> name;
		string command="C:\\windows\\injector.exe "+name+" -notomost";
		system(command.c_str());
		system("pause");
		goto start;
	}else{
		cout << "��ѡ�Ҹ�ɶ�Ҷ�˵��û����" << endl;
		system("pause");
		goto start;		
	}
	return 0;
}

