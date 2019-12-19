package pivx.org.pivxwallet.ui.twofa_config;

import android.app.Activity;
import android.app.Fragment;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.graphics.drawable.ColorDrawable;
import android.os.Bundle;
import android.support.annotation.Nullable;
import android.app.DialogFragment;
import android.support.v4.app.FragmentActivity;
import android.support.v4.app.FragmentManager;
import android.support.v4.graphics.drawable.RoundedBitmapDrawable;
import android.support.v4.graphics.drawable.RoundedBitmapDrawableFactory;
import android.text.SpannableString;
import android.text.style.UnderlineSpan;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ExpandableListView;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;
import android.widget.ToggleButton;

import com.google.zxing.WriterException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import global.PivxModule;
import pivx.org.pivxwallet.PivxApplication;
import pivx.org.pivxwallet.R;
import pivx.org.pivxwallet.ui.base.BaseDrawerActivity;
import pivx.org.pivxwallet.ui.base.PivxActivity;
import pivx.org.pivxwallet.ui.transaction_send_activity.IOnFocusListenable;
import pivx.org.pivxwallet.ui.transaction_send_activity.SendActivity;
import pivx.org.pivxwallet.utils.AppConf;
import pivx.org.pivxwallet.utils.Base32String;
import pivx.org.pivxwallet.utils.DapsController;
import pivx.org.pivxwallet.utils.FeeAdapter;
import pivx.org.pivxwallet.utils.NavigationUtils;
import pivx.org.pivxwallet.utils.NodeAdapter;
import pivx.org.pivxwallet.utils.NodeInfo;
import pivx.org.pivxwallet.utils.PasscodeGenerator;
import pivx.org.pivxwallet.utils.TotpCounter;
import pivx.org.pivxwallet.utils.Utilities;

import static android.content.Context.INPUT_METHOD_SERVICE;
import static android.graphics.Color.WHITE;
import static pivx.org.pivxwallet.utils.AndroidUtils.copyToClipboard;
import static pivx.org.pivxwallet.utils.QrUtils.encodeAsBitmap;

/**
 * Created by Neoperol on 5/4/17.
 */

public class TwoFAConfigActivity extends Fragment implements View.OnClickListener {
    PivxApplication pivxApplication;
    PivxModule pivxModule;
    DapsController daps;
    private FragmentActivity myContext;

    private Logger logger = LoggerFactory.getLogger(TwoFAConfigActivity.class);

    private View root;
    private TextView code1, code2, code3, code4, code5, code6;
    private ToggleButton twofa_status;
    private Button btnDay, btnWeek, btnMonth;
    private TwoFAQRDialog qrDialog;
    private TwoFADialog dialog;
    private SuccessDialog success_dialog;

    public View onCreateView(LayoutInflater inflater, @Nullable ViewGroup container, Bundle savedInstanceState) {
        pivxApplication = PivxActivity.pivxApplication;
        pivxModule = PivxActivity.pivxModule;
        daps = PivxActivity.daps;

        View root = inflater.inflate(R.layout.fragment_2fa_settings, container, false);
        twofa_status = (ToggleButton) root.findViewById(R.id.twofa_state);
        btnDay = (Button) root.findViewById(R.id.btnDay);
        btnWeek = (Button) root.findViewById(R.id.btnWeek);
        btnMonth = (Button) root.findViewById(R.id.btnMonth);

        code1 = (TextView) root.findViewById(R.id.code_1);
        code2 = (TextView) root.findViewById(R.id.code_2);
        code3 = (TextView) root.findViewById(R.id.code_3);
        code4 = (TextView) root.findViewById(R.id.code_4);
        code5 = (TextView) root.findViewById(R.id.code_5);
        code6 = (TextView) root.findViewById(R.id.code_6);

        btnDay.setOnClickListener(this);
        btnWeek.setOnClickListener(this);
        btnMonth.setOnClickListener(this);
        twofa_status.setOnClickListener(this);

        AppConf appConf = pivxApplication.getAppConf();
        String status = appConf.getTwoFA();
        if (status.compareTo("enabled") == 0) {
            twofa_status.setChecked(true);
            enable_2fa();
        }
        else {
            twofa_status.setChecked(false);
            disable_2fa();
        }

        return root;
    }

    @Override
    public void onAttach(Activity activity) {
        myContext = (FragmentActivity) activity;
        super.onAttach(activity);
    }


    @Override
    public void onResume() {
        super.onResume();

        if(getActivity().getCurrentFocus()!=null) {
            InputMethodManager inputMethodManager = (InputMethodManager) getActivity().getSystemService(INPUT_METHOD_SERVICE);
            inputMethodManager.hideSoftInputFromWindow(getActivity().getCurrentFocus().getWindowToken(), 0);
        }
    }

    @Override
    public void onClick(View v) {
        int id = v.getId();
        AppConf appConf = pivxApplication.getAppConf();

        if (id == R.id.btnDay){
            appConf.saveTwoFAPeriod("1");
            btnDay.setTextColor(Color.RED);
            btnWeek.setTextColor(Color.WHITE);
            btnMonth.setTextColor(Color.WHITE);
        } else if (id == R.id.btnWeek) {
            appConf.saveTwoFAPeriod("7");
            btnDay.setTextColor(Color.WHITE);
            btnWeek.setTextColor(Color.RED);
            btnMonth.setTextColor(Color.WHITE);
        } else if (id == R.id.btnMonth) {
            appConf.saveTwoFAPeriod("31");
            btnDay.setTextColor(Color.WHITE);
            btnWeek.setTextColor(Color.WHITE);
            btnMonth.setTextColor(Color.RED);
        } else if (id == R.id.twofa_state) {
            if (twofa_status.isChecked()) {
                if (qrDialog != null){
                    qrDialog = null;
                }
                qrDialog = TwoFAQRDialog.newInstance(daps, TwoFAConfigActivity.this);
                qrDialog.show(getFragmentManager(), "twofa_qr_dialog");
            }
            else {
                appConf.saveTwoFA("disabled");
                appConf.saveTwoFAPeriod("1");
                appConf.saveTwoFACode("");
                appConf.saveTwoFALastTime("0");
                disable_2fa();
            }
        }
    }

    private void enable_2fa() {
        btnDay.setEnabled(true);
        btnWeek.setEnabled(true);
        btnMonth.setEnabled(true);

        code1.setEnabled(true);
        code2.setEnabled(true);
        code3.setEnabled(true);
        code4.setEnabled(true);
        code5.setEnabled(true);
        code6.setEnabled(true);

        AppConf appConf = pivxApplication.getAppConf();
        String code = appConf.getTwoFACode();
        if (code.compareTo("") != 0) {
            String[] splitCode = code.split("");
            code1.setText(splitCode[1]);
            code2.setText(splitCode[2]);
            code3.setText(splitCode[3]);
            code4.setText(splitCode[4]);
            code5.setText(splitCode[5]);
            code6.setText(splitCode[6]);
        }

        String period = appConf.getTwoFAPeriod();
        if (period.compareTo("1") == 0)
            btnDay.setTextColor(Color.RED);
        else if (period.compareTo("7") == 0)
            btnWeek.setTextColor(Color.RED);
        else if (period.compareTo("31") == 0)
            btnMonth.setTextColor(Color.RED);
    }

    private void disable_2fa() {
        btnDay.setEnabled(false);
        btnDay.setTextColor(0x7FFFFFFF);
        btnWeek.setEnabled(false);
        btnWeek.setTextColor(0x7FFFFFFF);
        btnMonth.setEnabled(false);
        btnMonth.setTextColor(0x7FFFFFFF);

        code1.setEnabled(false);
        code2.setEnabled(false);
        code3.setEnabled(false);
        code4.setEnabled(false);
        code5.setEnabled(false);
        code6.setEnabled(false);

        code1.setText("");
        code2.setText("");
        code3.setText("");
        code4.setText("");
        code5.setText("");
        code6.setText("");
    }

    public void qrdialog_finished() {
        if (dialog != null){
            dialog = null;
        }
        dialog = TwoFADialog.newInstance(daps, TwoFAConfigActivity.this);
        dialog.show(getFragmentManager(), "twofa_dialog");
    }

    public void qrdialog_rejected() {
        twofa_status.setChecked(false);
    }

    public void dialog_finished() {
        AppConf appConf = pivxApplication.getAppConf();
        appConf.saveTwoFA("enabled");
        enable_2fa();

        if (success_dialog != null) {
            success_dialog = null;
        }

        success_dialog = SuccessDialog.newInstance();
        success_dialog.show(getFragmentManager(), "twofa_success_dialog");
    }

    public void dialog_rejected() {
        twofa_status.setChecked(false);
    }

    public static class TwoFAQRDialog extends android.app.DialogFragment {
        private Fragment parentFragment;
        private View root;
        private DapsController rpc;
        private ImageView img_qr;
        private TextView underline_text;
        private LinearLayout copy_data;
        private String URI;

        @Nullable
        @Override
        public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
            try {
                getDialog().getWindow().setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
                root = inflater.inflate(R.layout.twofa_qr_dialog, container);
                //root = getActivity().getLayoutInflater().inflate(R.layout.twofa_qr_dialog, new LinearLayout(getActivity()), false);

                underline_text = (TextView) root.findViewById(R.id.underline_text);
                img_qr = (ImageView) root.findViewById(R.id.img_qr);
                copy_data = (LinearLayout) root.findViewById(R.id.copy_data);

                if (img_qr != null) {
                    int px = convertDpToPx(225);
                    //-----Test Purpose
                    String address = PivxApplication.getInstance().getModule().getStealthAddress();//(String)rpc.callRPC("getAccountAddress");
                    address = address.replaceAll("[^A-Za-z]","");
                    URI = "otpauth://totp/dapscoin:test@test.com?secret=" + address + "&issuer=dapscoin&algorithm=SHA1&digits=6&period=30";
                    Bitmap qrBitmap = null;
                    try {
                        qrBitmap = encodeAsBitmap(URI, px, px, Color.parseColor("#1A1A1A"), WHITE);
                        RoundedBitmapDrawable circularBitmapDrawable = RoundedBitmapDrawableFactory.create(getResources(), qrBitmap);
                        circularBitmapDrawable.setCornerRadius(7);
                        img_qr.setImageDrawable(circularBitmapDrawable);
                    } catch (WriterException e) {
                        e.printStackTrace();
                    }

                    SpannableString content = new SpannableString(URI);
                    content.setSpan(new UnderlineSpan(), 0, content.length(), 0);
                    underline_text.setText(content);

                    copy_data.setVisibility(View.VISIBLE);
                }

                root.findViewById(R.id.btn_next).setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View v) {
                        dismiss();
                        ((TwoFAConfigActivity)parentFragment).qrdialog_finished();
                    }
                });

                root.findViewById(R.id.btn_cancel).setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View v) {
                        dismiss();
                        ((TwoFAConfigActivity)parentFragment).qrdialog_rejected();
                    }
                });

                root.findViewById(R.id.img_copy).setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View v) {
                        copyToClipboard(getActivity(), URI);
                        Toast.makeText(getActivity(), R.string.copy_uri, Toast.LENGTH_LONG).show();
                    }
                });
            }catch (Exception e){
                Toast.makeText(getActivity(),R.string.error_generic,Toast.LENGTH_SHORT).show();
                dismiss();
            }
            return root;
        }

        public int convertDpToPx(int dp) {
            return (int)(dp * getActivity().getResources().getDisplayMetrics().density);
        }

        public void updateData(DapsController controller) {
            this.rpc = controller;
        }

        public void setFragment(Fragment fragment) {
            this.parentFragment = fragment;
        }

        public static TwoFAQRDialog newInstance(DapsController controller, Fragment fragment) {
            TwoFAQRDialog dlg = new TwoFAQRDialog();
            dlg.setCancelable(false);
            dlg.updateData(controller);
            dlg.setFragment(fragment);
            return dlg;
        }
    }

    public static class TwoFADialog extends DialogFragment implements CutCopyPasteEditText.OnCutCopyPasteListener {
        Fragment parentFragment;
        private View root;
        private DapsController rpc;
        private CutCopyPasteEditText code1, code2, code3, code4, code5, code6;

        @Nullable
        @Override
        public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
            try {
                getDialog().getWindow().setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
                root = inflater.inflate(R.layout.twofa_dialog, container);
                code1= (CutCopyPasteEditText) root.findViewById(R.id.code_1);
                code1.setOnCutCopyPasteListener(this);
                code2= (CutCopyPasteEditText) root.findViewById(R.id.code_2);
                code2.setOnCutCopyPasteListener(this);
                code3= (CutCopyPasteEditText) root.findViewById(R.id.code_3);
                code3.setOnCutCopyPasteListener(this);
                code4= (CutCopyPasteEditText) root.findViewById(R.id.code_4);
                code4.setOnCutCopyPasteListener(this);
                code5= (CutCopyPasteEditText) root.findViewById(R.id.code_5);
                code5.setOnCutCopyPasteListener(this);
                code6= (CutCopyPasteEditText) root.findViewById(R.id.code_6);
                code6.setOnCutCopyPasteListener(this);

                root.findViewById(R.id.btn_confirm).setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View v) {
                        String code = "";
                        code += code1.getText().toString();
                        code += code2.getText().toString();
                        code += code3.getText().toString();
                        code += code4.getText().toString();
                        code += code5.getText().toString();
                        code += code6.getText().toString();

                        String address = PivxApplication.getInstance().getModule().getStealthAddress();//(String)rpc.callRPC("getAccountAddress");
                        address = address.replaceAll("[^A-Za-z]","");
                        String checkCode = null;
                        try {
                            checkCode = getCheckCode(address);
                        } catch (GeneralSecurityException e) {
                            e.printStackTrace();
                        } catch (Base32String.DecodingException e) {
                            e.printStackTrace();
                        }

                        if (checkCode.compareTo(code) != 0) {
                            Toast.makeText(getActivity(), "No match code", Toast.LENGTH_SHORT).show();
                            return;
                        }

                        AppConf appConf = ((TwoFAConfigActivity)parentFragment).pivxApplication.getAppConf();
                        appConf.saveTwoFACode(code);

                        dismiss();
                        ((TwoFAConfigActivity)parentFragment).dialog_finished();
                    }
                });

                root.findViewById(R.id.btn_cancel).setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View v) {
                        dismiss();
                        ((TwoFAConfigActivity)parentFragment).dialog_rejected();
                    }
                });
            }catch (Exception e){
                Toast.makeText(getActivity(),R.string.error_generic,Toast.LENGTH_SHORT).show();
                dismiss();
            }
            return root;
        }

        private String getCheckCode(String secret) throws GeneralSecurityException,
                Base32String.DecodingException {
            final byte[] keyBytes = Base32String.decode(secret);
            Mac mac = Mac.getInstance("HMACSHA1");
            mac.init(new SecretKeySpec(keyBytes, ""));
            PasscodeGenerator pcg = new PasscodeGenerator(mac);
            TotpCounter mTotpCounter = new TotpCounter(30);
            return pcg.generateResponseCode(mTotpCounter.getValueAtTime(Utilities.millisToSeconds(System.currentTimeMillis())));
        }

        public void updateData(DapsController controller) {
            this.rpc = controller;
        }

        public void setFragment(android.app.Fragment fragment) {
            this.parentFragment = fragment;
        }

        public static TwoFADialog newInstance(DapsController controller, android.app.Fragment fragment) {
            TwoFADialog dlg = new TwoFADialog();
            dlg.setCancelable(false);
            dlg.updateData(controller);
            dlg.setFragment(fragment);
            return dlg;
        }

        @Override
        public void onCut() {

        }

        @Override
        public void onCopy() {

        }

        @Override
        public void onPaste(EditText v) {
            ClipboardManager clipboardManager = (ClipboardManager)getActivity().getSystemService(Context.CLIPBOARD_SERVICE);

            if(clipboardManager.hasPrimaryClip()) {
                ClipData.Item item = clipboardManager.getPrimaryClip().getItemAt(0);

                String ptext = item.getText().toString();
                if (ptext.length() != 6) {
                    v.setText("");
                    return;
                }

                String[] splitCode = ptext.split("");
                code1.setText(splitCode[1]);
                code2.setText(splitCode[2]);
                code3.setText(splitCode[3]);
                code4.setText(splitCode[4]);
                code5.setText(splitCode[5]);
                code6.setText(splitCode[6]);
            }
        }
    }

    public static class SuccessDialog extends DialogFragment{
        private View root;

        @Nullable
        @Override
        public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
            try {
                getDialog().getWindow().setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
                root = inflater.inflate(R.layout.twofa_success_dialog, container);

                root.findViewById(R.id.btn_done).setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View v) {
                        dismiss();
                    }
                });
            }catch (Exception e){
                Toast.makeText(getActivity(),R.string.error_generic,Toast.LENGTH_SHORT).show();
                dismiss();
            }
            return root;
        }

        public static SuccessDialog newInstance() {
            SuccessDialog dlg = new SuccessDialog();
            dlg.setCancelable(false);
            return dlg;
        }
    }
}
