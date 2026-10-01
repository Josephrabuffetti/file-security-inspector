package inspector;

import javax.swing.*;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;

public final class Main {
    public static void main(String[] args) {
        if (args.length == 1 && args[0].equals("--help")) {
            System.out.println("File Security Inspector Basic\njava -jar file-security-inspector.jar\njava -jar file-security-inspector.jar --scan <file>\nLocal static checks only. Exit 0: inspection completed (not proof of safety); 1: inspection failed; 2: invalid arguments.");
        } else if (args.length == 2 && args[0].equals("--scan")) {
            try { System.out.print(Inspector.inspect(Path.of(args[1])).report()); }
            catch (Exception e) { System.err.println("Inspection failed: " + Inspector.safe(String.valueOf(e.getMessage()))); System.exit(1); }
        } else if (args.length != 0) {
            System.err.println("Usage: java -jar file-security-inspector.jar [--scan <file> | --help]"); System.exit(2);
        } else SwingUtilities.invokeLater(Main::showWindow);
    }

    private static JTextArea textArea() {
        JTextArea area = new JTextArea();
        area.setEditable(false);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
        area.setMargin(new Insets(14, 14, 14, 14));
        return area;
    }
    private static void showWindow() {
        JFrame frame = new JFrame("File Security Inspector — Basic v1.0.0");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(1020, 740);
        frame.setMinimumSize(new Dimension(700, 480));
        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 10));
        JButton select = new JButton("Choose file & inspect");
        JButton save = new JButton("Save report");
        save.setEnabled(false);
        JLabel status = new JLabel("Local inspection • files up to 20 MiB • files are never executed");
        top.add(select); top.add(save);
        JTextArea report = textArea();
        report.setLineWrap(true); report.setWrapStyleWord(true);
        report.setText("Choose a file to inspect its type, SHA-256 fingerprint, and readable text.\n\nSupported text: UTF-8, or UTF-16 with a byte-order mark, up to 1 MiB.\n\nThis basic tool identifies indicators for review. It cannot certify that a file is safe.");
        JTextArea source = textArea();
        source.setText("Readable file contents will appear here with line numbers.");
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Findings & fingerprint", new JScrollPane(report));
        tabs.addTab("Readable contents", new JScrollPane(source));
        frame.add(top, BorderLayout.NORTH); frame.add(tabs, BorderLayout.CENTER);
        status.setBorder(BorderFactory.createEmptyBorder(8, 12, 8, 12));
        frame.add(status, BorderLayout.SOUTH);
        select.addActionListener(event -> {
            JFileChooser chooser = new JFileChooser();
            if (chooser.showOpenDialog(frame) != JFileChooser.APPROVE_OPTION) return;
            Path path = chooser.getSelectedFile().toPath();
            select.setEnabled(false); save.setEnabled(false);
            report.setText("Inspecting…"); source.setText(""); status.setText("Reading file locally…");
            new SwingWorker<Inspector.Result, Void>() {
                protected Inspector.Result doInBackground() throws Exception { return Inspector.inspect(path); }
                protected void done() {
                    try {
                        Inspector.Result result = get();
                        report.setText(result.report()); report.setCaretPosition(0);
                        if (result.source() == null) source.setText("Readable contents unavailable. See the report limitations.");
                        else {
                            String[] lines = result.source().split("\\R", -1);
                            StringBuilder numbered = new StringBuilder();
                            for (int i = 0; i < lines.length; i++) numbered.append(i + 1).append(" | ").append(Inspector.safe(lines[i])).append('\n');
                            source.setText(numbered.toString()); source.setCaretPosition(0);
                        }
                        save.setEnabled(true); status.setText("Inspection complete • " + result.findings().size() + " indicators • review limitations");
                    } catch (Exception ex) {
                        Throwable cause = ex.getCause() == null ? ex : ex.getCause();
                        report.setText("Inspection failed.\n" + Inspector.safe(String.valueOf(cause.getMessage())));
                        status.setText("No inspection result available.");
                    } finally { select.setEnabled(true); }
                }
            }.execute();
        });
        save.addActionListener(event -> {
            JFileChooser chooser = new JFileChooser(); chooser.setSelectedFile(new java.io.File("inspection-report.txt"));
            if (chooser.showSaveDialog(frame) != JFileChooser.APPROVE_OPTION) return;
            Path destination = chooser.getSelectedFile().toPath();
            if (Files.exists(destination) && JOptionPane.showConfirmDialog(frame, "Replace the existing file?", "Save report", JOptionPane.YES_NO_OPTION) != JOptionPane.YES_OPTION) return;
            try { Files.writeString(destination, report.getText(), StandardCharsets.UTF_8); status.setText("Report saved."); }
            catch (Exception ex) { JOptionPane.showMessageDialog(frame, "Could not save report: " + ex.getMessage(), "Save failed", JOptionPane.ERROR_MESSAGE); }
        });
        frame.setLocationRelativeTo(null); frame.setVisible(true);
    }
}

