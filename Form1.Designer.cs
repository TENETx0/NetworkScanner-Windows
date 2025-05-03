namespace Tenetx01
{
    partial class Form1
    {
        /// <summary>
        ///  Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        ///  Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        ///  Required method for Designer support - do not modify
        ///  the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            components = new System.ComponentModel.Container();
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(Form1));
            label1 = new Label();
            textBox1 = new TextBox();
            richTextBox1 = new RichTextBox();
            button1 = new Button();
            linkLabel1 = new LinkLabel();
            notifyIcon1 = new NotifyIcon(components);
            process1 = new System.Diagnostics.Process();
            timer1 = new System.Windows.Forms.Timer(components);
            progressBar1 = new ProgressBar();
            saveFileDialog1 = new SaveFileDialog();
            checkBox1 = new CheckBox();
            checkBox2 = new CheckBox();
            checkBox3 = new CheckBox();
            checkBox4 = new CheckBox();
            checkBox5 = new CheckBox();
            checkBox6 = new CheckBox();
            checkBox7 = new CheckBox();
            checkBox8 = new CheckBox();
            button2 = new Button();
            button3 = new Button();
            button4 = new Button();
            SuspendLayout();
            // 
            // label1
            // 
            label1.AutoSize = true;
            label1.Font = new Font("Yu Gothic UI Semibold", 9F, FontStyle.Bold, GraphicsUnit.Point, 0);
            label1.Location = new Point(460, 25);
            label1.Name = "label1";
            label1.Size = new Size(155, 25);
            label1.TabIndex = 0;
            label1.Text = "Network Scanner";
            // 
            // textBox1
            // 
            textBox1.Location = new Point(25, 92);
            textBox1.Name = "textBox1";
            textBox1.PlaceholderText = "Enter IP Address: Eg- 192.168.1.1-192.168.1.50";
            textBox1.Size = new Size(790, 31);
            textBox1.TabIndex = 1;
            textBox1.TextChanged += textBox1_TextChanged;
            // 
            // richTextBox1
            // 
            richTextBox1.Location = new Point(25, 226);
            richTextBox1.Name = "richTextBox1";
            richTextBox1.ReadOnly = true;
            richTextBox1.Size = new Size(1096, 310);
            richTextBox1.TabIndex = 2;
            richTextBox1.Text = "";
            richTextBox1.TextChanged += richTextBox1_TextChanged;
            // 
            // button1
            // 
            button1.BackgroundImage = Properties.Resources.ChatGPT_Image_May_2__2025__07_25_24_PM;
            button1.Location = new Point(861, 85);
            button1.Margin = new Padding(12);
            button1.Name = "button1";
            button1.Size = new Size(112, 44);
            button1.TabIndex = 3;
            button1.Text = "Scan";
            button1.UseVisualStyleBackColor = true;
            button1.Click += button1_Click;
            // 
            // linkLabel1
            // 
            linkLabel1.AutoSize = true;
            linkLabel1.LinkColor = Color.Red;
            linkLabel1.Location = new Point(1059, 25);
            linkLabel1.Name = "linkLabel1";
            linkLabel1.Size = new Size(62, 25);
            linkLabel1.TabIndex = 4;
            linkLabel1.TabStop = true;
            linkLabel1.Text = "Help ?";
            linkLabel1.VisitedLinkColor = Color.Red;
            linkLabel1.LinkClicked += linkLabel1_LinkClicked;
            // 
            // notifyIcon1
            // 
            notifyIcon1.Text = "notifyIcon1";
            notifyIcon1.Visible = true;
            // 
            // process1
            // 
            process1.StartInfo.Domain = "";
            process1.StartInfo.LoadUserProfile = false;
            process1.StartInfo.Password = null;
            process1.StartInfo.StandardErrorEncoding = null;
            process1.StartInfo.StandardInputEncoding = null;
            process1.StartInfo.StandardOutputEncoding = null;
            process1.StartInfo.UseCredentialsForNetworkingOnly = false;
            process1.StartInfo.UserName = "";
            process1.SynchronizingObject = this;
            process1.Exited += process1_Exited;
            // 
            // progressBar1
            // 
            progressBar1.Location = new Point(25, 542);
            progressBar1.Name = "progressBar1";
            progressBar1.Size = new Size(1096, 23);
            progressBar1.TabIndex = 5;
            progressBar1.Click += progressBar1_Click;
            // 
            // saveFileDialog1
            // 
            saveFileDialog1.FileOk += saveFileDialog1_FileOk;
            // 
            // checkBox1
            // 
            checkBox1.AutoSize = true;
            checkBox1.Location = new Point(25, 143);
            checkBox1.Name = "checkBox1";
            checkBox1.Size = new Size(119, 29);
            checkBox1.TabIndex = 6;
            checkBox1.Text = "Basic Scan";
            checkBox1.UseVisualStyleBackColor = true;
            checkBox1.CheckedChanged += checkBox1_CheckedChanged;
            // 
            // checkBox2
            // 
            checkBox2.AutoSize = true;
            checkBox2.Location = new Point(184, 143);
            checkBox2.Name = "checkBox2";
            checkBox2.Size = new Size(141, 29);
            checkBox2.TabIndex = 7;
            checkBox2.Text = "Health Check";
            checkBox2.UseVisualStyleBackColor = true;
            checkBox2.CheckedChanged += checkBox2_CheckedChanged;
            // 
            // checkBox3
            // 
            checkBox3.AutoSize = true;
            checkBox3.Location = new Point(365, 143);
            checkBox3.Name = "checkBox3";
            checkBox3.Size = new Size(185, 29);
            checkBox3.TabIndex = 8;
            checkBox3.Text = "Identify IoT Device";
            checkBox3.UseVisualStyleBackColor = true;
            checkBox3.CheckedChanged += checkBox3_CheckedChanged;
            // 
            // checkBox4
            // 
            checkBox4.AutoSize = true;
            checkBox4.Location = new Point(617, 143);
            checkBox4.Name = "checkBox4";
            checkBox4.Size = new Size(149, 29);
            checkBox4.TabIndex = 9;
            checkBox4.Text = "Crypto Check ";
            checkBox4.UseVisualStyleBackColor = true;
            checkBox4.CheckedChanged += checkBox4_CheckedChanged;
            // 
            // checkBox5
            // 
            checkBox5.AutoSize = true;
            checkBox5.Location = new Point(25, 178);
            checkBox5.Name = "checkBox5";
            checkBox5.Size = new Size(148, 29);
            checkBox5.TabIndex = 10;
            checkBox5.Text = "Advance Scan";
            checkBox5.UseVisualStyleBackColor = true;
            checkBox5.CheckedChanged += checkBox5_CheckedChanged;
            // 
            // checkBox6
            // 
            checkBox6.AutoSize = true;
            checkBox6.Location = new Point(184, 178);
            checkBox6.Name = "checkBox6";
            checkBox6.Size = new Size(175, 29);
            checkBox6.TabIndex = 11;
            checkBox6.Text = "Proxy / VPN Scan";
            checkBox6.UseVisualStyleBackColor = true;
            checkBox6.CheckedChanged += checkBox6_CheckedChanged;
            // 
            // checkBox7
            // 
            checkBox7.AutoSize = true;
            checkBox7.Location = new Point(365, 178);
            checkBox7.Name = "checkBox7";
            checkBox7.Size = new Size(235, 29);
            checkBox7.TabIndex = 12;
            checkBox7.Text = "Open File Share Detector";
            checkBox7.UseVisualStyleBackColor = true;
            checkBox7.CheckedChanged += checkBox7_CheckedChanged;
            // 
            // checkBox8
            // 
            checkBox8.AutoSize = true;
            checkBox8.Location = new Point(617, 178);
            checkBox8.Name = "checkBox8";
            checkBox8.Size = new Size(198, 29);
            checkBox8.TabIndex = 13;
            checkBox8.Text = "Port to App Mapper";
            checkBox8.UseVisualStyleBackColor = true;
            checkBox8.CheckedChanged += checkBox8_CheckedChanged;
            // 
            // button2
            // 
            button2.BackgroundImage = Properties.Resources.ChatGPT_Image_May_2__2025__07_25_24_PM;
            button2.Location = new Point(997, 85);
            button2.Margin = new Padding(12);
            button2.Name = "button2";
            button2.Size = new Size(112, 44);
            button2.TabIndex = 14;
            button2.Text = "Stop";
            button2.UseVisualStyleBackColor = true;
            button2.Click += button2_Click;
            // 
            // button3
            // 
            button3.BackgroundImage = Properties.Resources.ChatGPT_Image_May_2__2025__07_25_24_PM;
            button3.Location = new Point(861, 163);
            button3.Margin = new Padding(12);
            button3.Name = "button3";
            button3.Size = new Size(112, 44);
            button3.TabIndex = 15;
            button3.Text = "Clear";
            button3.UseVisualStyleBackColor = true;
            button3.Click += button3_Click;
            // 
            // button4
            // 
            button4.BackgroundImage = Properties.Resources.ChatGPT_Image_May_2__2025__07_25_24_PM;
            button4.Location = new Point(997, 163);
            button4.Margin = new Padding(12);
            button4.Name = "button4";
            button4.Size = new Size(112, 44);
            button4.TabIndex = 16;
            button4.Text = "Save";
            button4.UseVisualStyleBackColor = true;
            button4.Click += button4_Click;
            // 
            // Form1
            // 
            AutoScaleDimensions = new SizeF(10F, 25F);
            AutoScaleMode = AutoScaleMode.Font;
            BackgroundImage = Properties.Resources.ChatGPT_Image_May_2__2025__07_25_24_PM;
            ClientSize = new Size(1154, 577);
            Controls.Add(button4);
            Controls.Add(button3);
            Controls.Add(button2);
            Controls.Add(checkBox8);
            Controls.Add(checkBox7);
            Controls.Add(checkBox6);
            Controls.Add(checkBox5);
            Controls.Add(checkBox4);
            Controls.Add(checkBox3);
            Controls.Add(checkBox2);
            Controls.Add(checkBox1);
            Controls.Add(progressBar1);
            Controls.Add(linkLabel1);
            Controls.Add(button1);
            Controls.Add(richTextBox1);
            Controls.Add(textBox1);
            Controls.Add(label1);
            FormBorderStyle = FormBorderStyle.FixedSingle;
            Icon = (Icon)resources.GetObject("$this.Icon");
            MaximizeBox = false;
            Name = "Form1";
            Text = "Tenetx01";
            ResumeLayout(false);
            PerformLayout();
        }

        #endregion

        private Label label1;
        private TextBox textBox1;
        private RichTextBox richTextBox1;
        private Button button1;
        private LinkLabel linkLabel1;
        private NotifyIcon notifyIcon1;
        private System.Diagnostics.Process process1;
        private System.Windows.Forms.Timer timer1;
        private ProgressBar progressBar1;
        private SaveFileDialog saveFileDialog1;
        private CheckBox checkBox4;
        private CheckBox checkBox3;
        private CheckBox checkBox2;
        private CheckBox checkBox1;
        private CheckBox checkBox7;
        private CheckBox checkBox6;
        private CheckBox checkBox5;
        private CheckBox checkBox8;
        private Button button2;
        private Button button3;
        private Button button4;
    }
}
