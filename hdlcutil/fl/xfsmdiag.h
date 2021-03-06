// generated by Fast Light User Interface Designer (fluid) version 1.00

#ifndef xfsmdiag_h
#define xfsmdiag_h
#include <FL/Fl.H>
#include <FL/Fl_Window.H>
extern Fl_Window *scopewindow;
#include <FL/Fl_Box.H>
#include "xfsmdiag_main.h"
extern scope *scdisp;
#include <FL/Fl_Button.H>
extern void cb_cleargr(Fl_Button*, long);
extern Fl_Button *cleargr;
#include <FL/Fl_Group.H>
extern Fl_Group *scopemode;
#include <FL/Fl_Check_Button.H>
extern void cb_mode(Fl_Check_Button*, long);
extern Fl_Check_Button *sm_off;
extern Fl_Check_Button *sm_input;
extern Fl_Check_Button *sm_demod;
extern Fl_Check_Button *sm_constell;
extern Fl_Check_Button *sm_dcd;
extern void cb_quit(Fl_Button*, long);
extern Fl_Button *quit;
#include <FL/Fl_Round_Button.H>
extern Fl_Round_Button *st_dcd;
extern Fl_Round_Button *st_ptt;
#include <FL/Fl_Output.H>
extern Fl_Output *modename;
extern Fl_Output *drivername;
Fl_Window* create_the_forms();
#endif
