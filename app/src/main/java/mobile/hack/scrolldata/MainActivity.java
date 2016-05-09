package mobile.hack.scrolldata;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.IntentFilter;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.NfcAdapter;
import android.nfc.NfcManager;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.nfc.tech.MifareClassic;
import android.nfc.tech.MifareUltralight;
import android.nfc.tech.NdefFormatable;
import android.nfc.tech.NfcA;
import android.nfc.tech.TagTechnology;
import android.os.Bundle;
import android.os.Parcelable;
import android.support.v4.app.FragmentActivity;
import android.support.v4.app.FragmentTransaction;
import android.text.Html;
import android.text.method.ScrollingMovementMethod;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.TextView;
import android.widget.Toast;
import android.widget.ViewAnimator;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Calendar;
import java.util.StringTokenizer;


public class MainActivity extends Activity {

    private TextView textView;

    //private NfcManager nfcManager;
    //private NfcAdapter nfcAdapter;
    //private PendingIntent pendingIntent;
    //private IntentFilter intentFilter;
    static public byte[] SELECT_PPSE = {(byte)0x00,(byte)0xA4,(byte)0x04,(byte)0x00,(byte)0x0E,(byte)0x32,(byte)0x50,(byte)0x41,(byte)0x59,(byte)0x2E,(byte)0x53,(byte)0x59,(byte)0x53,(byte)0x2E,(byte)0x44,(byte)0x44,(byte)0x46,(byte)0x30,(byte)0x31,(byte)0x00};

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_nfcsniff);

        textView = (TextView) findViewById(R.id.textView);
        textView.setMovementMethod(new ScrollingMovementMethod());

        //nfcAdapter = NfcAdapter.getDefaultAdapter(this);

        //pendingIntent = PendingIntent.getActivity(this, 0, new Intent(this, getClass()), 0);

        //intentFilter = new IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED);

        // Fragment transactions sourced from online examples
        /*if (savedInstanceState == null) {
            FragmentTransaction transaction = getSupportFragmentManager().beginTransaction();
            CardReaderFragment fragment = new CardReaderFragment();
            //transaction.replace(R.id.sample_content_fragment, fragment);
            transaction.commit();
        }*/
    }

/*
    @Override
    protected void onStart() {
        super.onStart();
        append("Started");
    }

    @Override
    protected void onResume() {
        super.onResume();

        append(pendingIntent.toString());
        append("Resumed");
        String sss=getIntent().getAction();
        if (NfcAdapter.ACTION_NDEF_DISCOVERED.equals(sss)) {
            append("NDEF");
        } else if (NfcAdapter.ACTION_TAG_DISCOVERED.equals(sss)) {
            append("TAG");
        } else if (NfcAdapter.ACTION_TECH_DISCOVERED.equals(sss)) {
            append("TECH");
        } else {
            append("Unknown:" + sss.toString());
        }
    }*/

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);

        toast("Card Read");

        //Get the first piece of info about the Tag
        Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
        String tagToString = tag.toString();
        append("Tag toString: " + tagToString);
        append("Tag describe contents: " + tag.describeContents());

        //Attempt to retrieve a supported tech list from the tag
        String[] techList = tag.getTechList();
        String techListFull = "";
        for (String techItem : techList) {
            techListFull = techListFull.concat(techItem + "\n");
        }
        append("Tech List: " + techListFull);

        //IsoDep communication mode A connection logic
        append("IsoDep logic gate check:");
        if (tagToString != null && tagToString.contains("android.nfc.tech.IsoDep")) {
            append("IsoDep logic continues.");
            IsoDep isoDep = IsoDep.get(tag);

            try {
                append("IsoDep Connecting");
                isoDep.connect();

                byte[] bytesToSend;
                byte[] bytesReceived;

                if (isoDep.isConnected()) {
                    append("IsoDep connect success");

                    //TODO Test and complete this ISOdep branch. Make Selection dynamic

                    // Prepare request '2PAY.SYS.DDF01'
                    bytesToSend = stringToBytes("00 A4 04 00 0E 32 50 41 59 2E 53 59 53 2E 44 44 46 30 31 00");
                    append("Sending ASCII: " + new String(bytesToSend,"ISO-8859-1"));
                    append("Sending Bytes: " + Arrays.toString(bytesToSend));
                    append("Sending Hex: " + bytesToHex(bytesToSend));

                    // Send message '2PAY.SYS.DDF01' and receive response
                    bytesReceived = isoDep.transceive(bytesToSend);
                    String stringReceived = new String(bytesReceived,"ISO-8859-1");
                    append("Received Bytes: " + Arrays.toString(bytesReceived));
                    append("Received Hex: " + bytesToHex(bytesReceived));
                    append("Received ASCII: " + stringReceived);

                    // interpret response, true if contains mastercard
                    if (stringReceived.contains("MasterCard")) {

                        append("Mastercard application confirmed.");

                        // Form select string request
                        append("Selecting MasterCard AID Credit RID PIX");
                        bytesToSend = stringToBytes("00 A4 04 00 07 A0 00 00 00 04 10 10 00");
                        append("Sending ASCII: " + new String(bytesToSend,"ISO-8859-1"));
                        append("Sending Bytes: " + Arrays.toString(bytesToSend));
                        append("Sending Hex: " + bytesToHex(bytesToSend));

                        // Send formatted bytes request
                        bytesReceived = isoDep.transceive(bytesToSend);
                        stringReceived = new String(bytesReceived, "ISO-8859-1");
                        append("Received Bytes: " + Arrays.toString(bytesReceived));
                        append("Received Hex: " + bytesToHex(bytesReceived));
                        append("Received ASCII: " + stringReceived);


                        // Form select string request
                        // TODO fix issue in not receing 9000 response
                        append("Sending Get Processing Options GPO");
                        bytesToSend = stringToBytes("80 A8 00 00 01 83 00");
                        append("Sending ASCII: " + new String(bytesToSend,"ISO-8859-1"));
                        append("Sending Bytes: " + Arrays.toString(bytesToSend));
                        append("Sending Hex: " + bytesToHex(bytesToSend));

                        // Send formatted bytes request
                        bytesReceived = isoDep.transceive(bytesToSend);
                        stringReceived = new String(bytesReceived, "ISO-8859-1");
                        append("Received Bytes: " + Arrays.toString(bytesReceived));
                        append("Received Hex: " + bytesToHex(bytesReceived));
                        append("Received ASCII: " + stringReceived);

                        // Form select string request
                        append("Send READ RECORD");
                        bytesToSend = stringToBytes("00 B2 01 0C 00");
                        append("Sending ASCII: " + new String(bytesToSend,"ISO-8859-1"));
                        append("Sending Bytes: " + Arrays.toString(bytesToSend));
                        append("Sending Hex: " + bytesToHex(bytesToSend));

                        // Send formatted bytes request
                        bytesReceived = isoDep.transceive(bytesToSend);
                        stringReceived = new String(bytesReceived, "ISO-8859-1");
                        append("Received Bytes: " + Arrays.toString(bytesReceived));
                        append("Received Hex: " + bytesToHex(bytesReceived));
                        append("Received ASCII: " + stringReceived);

                        // Form file request bytes
                        /*byte[] recFiles = stringToBytes("00 B2 01 0C 00");

                        // Send and catch resp bytes for bytes for file request
                        byte[] messageBytes = isoDep.transceive(recFiles);
                        append("respFilesString: " + new String(Arrays.copyOfRange(messageBytes,
                                29,45),"ISO-8859-1"));
                        append("respFilesString: " + new String(Arrays.copyOfRange(messageBytes,
                                75,77),"ISO-8859-1"));
                        append("respFilesString: " + new String(Arrays.copyOfRange(messageBytes,
                                73,75),"ISO-8859-1"));*/

                    } else if (stringReceived.contains("Visa")) {
                        append("Visa application confirmed.");
                    }

                    /*byte[] SELECT = {
                            (byte) 0x00, // CLA Class
                            (byte) 0xA4, // INS Instruction
                            (byte) 0x04, // P1  Parameter 1
                            (byte) 0x00, // P2  Parameter 2
                            (byte) 0x0A, // Length
                            0x61,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x34 // AID

                            byte[] command = new byte[]{0x00, 0xA4, 0x04, 0x00, 0xA0, 0x00, 0x00, 0x00, 0x04};


                            byte[] responseAPDU;


                            //2PAY.SYS.DDF01
                            byte[] select_Dir = new byte[]{
                                    (byte)0x00, (byte)0xa4, (byte)0x04, (byte)0x00, (byte)0x0e,
                                    (byte)0x32, (byte)0x50, (byte)0x41, (byte)0x59, (byte)0x2e,
                                    (byte)0x53, (byte)0x59, (byte)0x53, (byte)0x2e, (byte)0x44,
                                    (byte)0x44, (byte)0x46, (byte)0x30, (byte)0x31
                            };

                            //Select CC Applet
                            byte[] select_Applet = new byte[]{
                                    (byte)0x00, (byte)0xa4, (byte)0x04, (byte)0x00, (byte)7,
                                    (byte)0xa0, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x04,
                                    (byte)0x30, (byte)0x60
                            };

                            //Send GET PROCESSING OPTIONS command
                            byte[] Send_Get = new byte[]{
                                    (byte)0x80,(byte)0xA8,(byte)0x00,(byte)0x00,(byte)0x02,
                                    (byte)0x83,(byte)0x00,
                                    (byte)0x00
                            };
                    };*/


                    //byte[] responseBytes = isoDep.transceive(SELECT_PPSE);


                    //TODO apply message response handler to Append and complete Bye allocation

                    /*
                    append(String.valueOf(responseBytes));
                    if ((responseBytes[0] == (byte) 0x90 && responseBytes[1] == (byte) 0x00)) {
                        append("selected applet");
                    } else {
                        append("could not select applet");
                    }*/


                } else {
                    append("IsoDep connect failed.");
                }

                append("IsoDep disconnecting.");
                isoDep.close();
            } catch (IOException e) {
                append("ERROR: IsoDep connect attempt failed: " + e.getMessage());
            }

        } else {
            append("did not enter IsoDep logic.");
        }


        //Near field communication mode A connection logic
        append("nfcA logic gate check:");
        if (tagToString != null && tagToString.contains("android.nfc.tech.NfcA")) {
            append("nfcA logic continues");
            NfcA nfcA = NfcA.get(tag);

            try {
                append("nfcA Connecting");
                nfcA.connect();

                if (nfcA.isConnected()) {
                    append("nfcA connect success");
                } else {
                    append("nfcA connect failed.");
                }

                append("nfcA disconnecting.");
                nfcA.close();
            } catch (IOException e) {
                append("ERROR: nfcA connect attempt failed: " + e.getMessage());
            }

        } else {
            append("did not enter nfcA logic.");
        }


        //NdefFormatable communication mode A connection logic
        append("NdefFormatable logic gate check:");
        if (tagToString != null && tagToString.contains("android.nfc.tech.NdefFormatable")) {
            append("NdefFormatable logic continues.");
            NdefFormatable ndefFormatable = NdefFormatable.get(tag);

            try {
                append("NdefFormatable Connecting");
                ndefFormatable.connect();
                if (ndefFormatable.isConnected()) {
                    append("NdefFormatable connect success");

                } else {
                    append("NdefFormatable connect failed.");
                }

                append("NdefFormatable disconnecting.");
                ndefFormatable.close();
            } catch (IOException e) {
                append("ERROR: NdefFormatable connect attempt failed: " + e.getMessage());
            }

        } else {
            append("did not enter NdefFormatable logic.");
        }


        //MiFare Classic Connect attempt
        append("Mifare Classic logic gate check:");
        if (tagToString != null && tagToString.contains("android.nfc.tech.MifareClassic")) {
            append("Entered Mifare Classic. Getting Tag");
            MifareClassic mifareClassic = MifareClassic.get(tag);
            try {
                append("Connecting to Mifare Classic tag");
                mifareClassic.connect();

                if (mifareClassic.isConnected()) {
                    append("Mifare classic Connected");
                    //Write MiFare Classic read code here
                } else {
                    append("Mifare classic failed to connect");
                }

                append("Mifare classic disconnecting");
                mifareClassic.close();
            } catch (IOException e) {
                    append("ERROR: Mifare Classic connect attempt failed: " + e.getMessage());
            }
        } else {
            append("Not entering Mifare Classic flow.");
        }


        //Enter the MiFare Ultralight Reader
        append("Mifare Ultralight logic gate check:");
        if (tagToString != null && tagToString.contains("android.nfc.tech.MifareUltralight")) {
            append("Entered Mifare Ultralight. Getting Tag");
            MifareUltralight mifare = MifareUltralight.get(tag);
            try {
                mifare.connect();


                if (mifare.isConnected()) {
                    append("Mifare Ultralight Connected");
                    byte[] part1 = mifare.readPages(4);
                    byte[] part2 = mifare.readPages(8);
                    byte[] payload = new byte[24]; // 24 is a pre-defined number

                    System.arraycopy(part1, 0, payload, 0, part1.length);
                    System.arraycopy(part2, 0, payload, part1.length, 8); // 8 = 24 - 16

                    String str = new String(payload, Charset.forName("US-ASCII"));
                    Log.d("", str+";");
                    append(String.valueOf(payload));
                } else {
                    append("Mifare Ultralight failed to connect");
                }
                append("Mifare Ultralight disconnecting");
                mifare.close();
            } catch (IOException e) {
                append("ERROR: Mifare Ultralight connect attempt failed: " + e.getMessage());
            }
        } else {
            append("Not entering Ultralight logic.");
        }

            // If the tag supports NDEF then get the list of messages
        /*if (NfcAdapter.ACTION_NDEF_DISCOVERED.equals(getIntent().getAction())) {
            NdefMessage[] msgs;
                append("NDEF Confirmed");
                Parcelable[] rawMsgs = intent.getParcelableArrayExtra(NfcAdapter.EXTRA_NDEF_MESSAGES);
                if (rawMsgs != null) {
                    msgs = new NdefMessage[rawMsgs.length];
                    for (int i = 0; i < rawMsgs.length; i++) {
                        msgs[i] = (NdefMessage) rawMsgs[i];
                    }
                    for (NdefMessage nMsg : msgs) {
                        append("NDEF Msg: " + String.valueOf(nMsg.toByteArray()));
                        NdefRecord[] ndefRecords = nMsg.getRecords();
                        for ( NdefRecord ndefRecord : ndefRecords) {
                            append("NDEF Record: " + String.valueOf(ndefRecord.getPayload()));
                        }
                    }
                }
        }*/

    }

    /*
    @Override
    protected void onPause() {
        super.onPause();
        append("Paused");
    }*/

    // Converts a String into Bytes ready for transmission over ISODEP
    protected byte[] stringToBytes(String hexstr) throws IOException {

        String[] hexbytes = hexstr.split("\\s");
        byte[] bytes = new byte[hexbytes.length];
        for (int i = 0; i < hexbytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hexbytes[i], 16);
        }
        return bytes;
    }

    protected String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }

    private void toast(String text) {
        append("Toasting: " + text);
        Toast.makeText(this, text, Toast.LENGTH_SHORT).show();
    }

    private void appendISODep(byte[] bytes) {
        for (byte byt : bytes) {
            System.out.println("Byte: " + byt);
        }
    }

    private void append(String text) {
        Calendar cal = Calendar.getInstance();
        String timeString = cal.get(cal.HOUR_OF_DAY) + ":" + cal.get(Calendar.MINUTE)+ "." +
                cal.get(Calendar.MILLISECOND);
        String printString = timeString + ": " + text ;
        if (printString.contains("ERROR")) {
            textView.append(Html.fromHtml("<font color=#FF0000>" + printString + "</font>"));
        } else {
            textView.append(Html.fromHtml("<font color=#0000A0>" + printString + "</font>"));
        }
        textView.append("\n");

        System.out.println(printString);
    }
}