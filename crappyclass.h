
#include "stdafx.h"

#ifndef CRAPPYCLASS_H
#define CRAPPYCLASS_H

using std::cout;
using std::endl;

class CrappyClass{
private:
	DWORD val1, val2;
	char q[7];

public:
	CrappyClass() { cout << "CrappyClass constructor " << endl; };
	virtual ~CrappyClass() { cout << "CrappyClass destructor" << endl; };

	void processIt(int a, int b) { processPhase1(1, 'q', 2, 3); processPhase2(2, 3); };

protected:

	virtual void processPhase1(int a, char b, int c, int d) { cout << " CrappyClass->phase1 " << endl; };
	virtual void processPhase2(int a, int b) { cout << "CrappyClass->phase2 " << endl; };
};


class DerivedCrappyClass : public CrappyClass{
protected:
	virtual ~DerivedCrappyClass(){ cout << "DerivedCrappyClass destructor" << endl; };
	virtual void processPhase1(int a, char b, int c, int d) { cout << "DerivedCrappyClass->phase1" << endl; };
	//virtual void processPhase2(int a, int b) { cout << "DerivedCrappyClass->phase2" << endl; };
};

#endif