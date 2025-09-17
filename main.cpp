#include<bits/stdc++.h>
#include<windows.h>
using namespace std;
bool file(string name) {
	ifstream file(name.c_str());
	return !file.fail();
}//查看文件是否存在 
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
		cout << "使用本软件前，请先同意用户条款!" << endl;
		cout << "请自行到浏览器打开https://zcygod.top/tiaokuan/以查看" << endl;
		cout << "本条款屏幕只会显示一次" << endl;
		cout << "\n\n\n请选择[Y/N]:"<< endl;
		char choosepppp;
		cin >> choosepppp;
		if(choosepppp=='Y'){
			cout << "您同意了条款" << endl; 
			system("echo > Tongyi");	
			system("cls");
		}else {
			cout << "您拒绝了条款" << endl; 
			return 0;
		}
	}
	ero();
	cout << "使用前，请确保本程序拥有管理员权限！" << endl;
	cout << "使用前，请确保本程序拥有管理员权限！" << endl;
	cout << "使用前，请确保本程序拥有管理员权限！" << endl;
	cout << "使用前，请确保本程序拥有管理员权限！" << endl;
	cout << "使用前，请确保本程序拥有管理员权限！" << endl;
	cout << "使用前，请确保本程序拥有管理员权限！" << endl;
	cout << "使用前，请确保本程序拥有管理员权限！" << endl;
	cout << "使用前，请确保本程序拥有管理员权限！" << endl;
	
	Sleep(2000);
	system("copy /Y .\\lib\\*.* C:\\Windows");
	start:
	cout << "请问你要执行的操作？" << endl;
	cout << "\n1.保护程序（本操作不可逆，因为zcygod水平不足）" << endl;
	cout << "\n2.我不知道别问我" <<endl; 
	int choose;
	cin >> choose;
	if(choose==1){
		system("cls");
		cout << "请输入您要保护的程序的进程名字（英语），常见进程名如下：谷歌浏览器chrome.exe,edge浏览器：msedge.exe" << endl;
		string name;
		cin >> name;
		string command="C:\\windows\\injector.exe "+name+" -notomost";
		system(command.c_str());
		system("pause");
		goto start;
	}else{
		cout << "？选我干啥我都说了没东西" << endl;
		system("pause");
		goto start;		
	}
	return 0;
}

