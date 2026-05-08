/**
 * Main class for the login system program
    Copyright (C) 2026  DanngDev/Volcar144
 */


package top.archiem.projects;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import static java.lang.System.out;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Random;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

/**
 * Simple login system with persistent account storage, admin controls,
 * an admin portal, and basic command-line interaction.
 */
public class LoginSystem {
    // File names used for persistent storage
    private static final String DEFAULT_ACCOUNTS_FILE = "accounts.csv";
    private static final String DEFAULT_ADMINS_FILE = "admins.txt";
    private static final String DEFAULT_LOCKOUTS_FILE = "lockouts.txt";
    private static final String SETTINGS_FILE = "settings.properties";
    private static final String SETTINGS_RESOURCE = "/default-settings.properties";
    private static final String CSV_HEADER = "username,password";
    private static final String DEFAULT_LOG_FILE = "login-system.log";

    // Default password settings
    private static final boolean DEFAULT_PASSWORD_STRENGTH_ENABLED = true;
    private static final int DEFAULT_PASSWORD_MIN_LENGTH = 8;
    private static final int DEFAULT_PASSWORD_MIN_NUMBERS = 0;
    private static final int DEFAULT_PASSWORD_MIN_SYMBOLS = 0;
    private static final int DEFAULT_PASSWORD_MIN_UPPERCASE = 1;
    private static final int DEFAULT_PASSWORD_MIN_LOWERCASE = 1;
    private static final int DEFAULT_PASSWORD_LOCKOUT_DURATION = 15;
    private static final int DEFAULT_PASSWORD_LOCKOUT_THRESHOLD = 5;
    private static final boolean DEFAULT_ALLOW_SPECIAL_CHARACTERS = true;
    private static final boolean DEFAULT_REQUIRE_SPECIAL_CHARACTERS = false;
    private static final boolean DEFAULT_REQUIRE_NUMERIC = false;
    private static final boolean DEFAULT_REQUIRE_UPPERCASE = false;
    private static final boolean DEFAULT_REQUIRE_LOWERCASE = false;
    private static final int DEFAULT_PASSWORD_COMPLEXITY_LEVEL = 2;

    private static boolean passwordEnabled = DEFAULT_PASSWORD_STRENGTH_ENABLED;
    private static int minLength = DEFAULT_PASSWORD_MIN_LENGTH;
    private static int minNumbers = DEFAULT_PASSWORD_MIN_NUMBERS;
    private static int minSymbols = DEFAULT_PASSWORD_MIN_SYMBOLS;
    private static int minUppercase = DEFAULT_PASSWORD_MIN_UPPERCASE;
    private static int minLowercase = DEFAULT_PASSWORD_MIN_LOWERCASE;
    private static int passwordLockoutDurationMinutes = DEFAULT_PASSWORD_LOCKOUT_DURATION;
    private static int passwordLockoutThreshold = DEFAULT_PASSWORD_LOCKOUT_THRESHOLD;
    private static boolean allowSpecialCharacters = DEFAULT_ALLOW_SPECIAL_CHARACTERS;
    private static boolean requireSpecialCharacters = DEFAULT_REQUIRE_SPECIAL_CHARACTERS;
    private static boolean requireNumeric = DEFAULT_REQUIRE_NUMERIC;
    private static boolean requireUppercase = DEFAULT_REQUIRE_UPPERCASE;
    private static boolean requireLowercase = DEFAULT_REQUIRE_LOWERCASE;
    private static int passwordComplexityLevel = DEFAULT_PASSWORD_COMPLEXITY_LEVEL;


    // Default maximum login attempts before application termination
    private static final int DEFAULT_LOGIN_ATTEMPTS = 5;

    // Application settings and logger/input scanner
    private static final Properties settings = new Properties();
    private static final Logger LOGGER = Logger.getLogger(LoginSystem.class.getName());
    private static final Scanner keyboard = new Scanner(System.in);
    private static int loginAttempts = DEFAULT_LOGIN_ATTEMPTS;
    private static String accountsFile = DEFAULT_ACCOUNTS_FILE;
    private static String adminsFile = DEFAULT_ADMINS_FILE;
    private static String lockoutsFile = DEFAULT_LOCKOUTS_FILE;
    private static String logFile = DEFAULT_LOG_FILE;
    private static boolean loggerInitialized = false;

    private static final String licenseBanner = """
            Java Login System  Copyright (C) 2026  DanngDev/Volcar144
            This program comes with ABSOLUTELY NO WARRANTY; for details, see the license agreement.
            This is free software, and you are welcome to redistribute it
            under certain conditions; see the license agreement for details.
            """;

    /**
     * Load settings from the properties file, creating a copy of the default
     * resource into the current working folder if the file does not exist.
     */
    private static void loadSettings() {
        File settingsFile = new File(SETTINGS_FILE);
        if (!settingsFile.exists()) {
            copyDefaultSettings(settingsFile);
        }

        try (FileInputStream input = new FileInputStream(settingsFile)) {
            settings.load(input);
            loginAttempts = Integer.parseInt(settings.getProperty("loginAttempts", String.valueOf(DEFAULT_LOGIN_ATTEMPTS)));
            accountsFile = settings.getProperty("accountsFile", DEFAULT_ACCOUNTS_FILE);
            adminsFile = settings.getProperty("adminsFile", DEFAULT_ADMINS_FILE);
            lockoutsFile = settings.getProperty("lockoutsFile", DEFAULT_LOCKOUTS_FILE);
            logFile = settings.getProperty("logFile", DEFAULT_LOG_FILE);
            passwordEnabled = Boolean.parseBoolean(settings.getProperty("strengthRequirementsEnabled", String.valueOf(DEFAULT_PASSWORD_STRENGTH_ENABLED)));
            minLength = Integer.parseInt(settings.getProperty("minLength", String.valueOf(DEFAULT_PASSWORD_MIN_LENGTH)));
            minNumbers = Integer.parseInt(settings.getProperty("minNumbers", String.valueOf(DEFAULT_PASSWORD_MIN_NUMBERS)));
            minSymbols = Integer.parseInt(settings.getProperty("minSymbols", String.valueOf(DEFAULT_PASSWORD_MIN_SYMBOLS)));
            minUppercase = Integer.parseInt(settings.getProperty("minUppercase", String.valueOf(DEFAULT_PASSWORD_MIN_UPPERCASE)));
            minLowercase = Integer.parseInt(settings.getProperty("minLowercase", String.valueOf(DEFAULT_PASSWORD_MIN_LOWERCASE)));
            passwordLockoutDurationMinutes = Integer.parseInt(settings.getProperty("passwordLockoutDurationMinutes", String.valueOf(DEFAULT_PASSWORD_LOCKOUT_DURATION)));
            passwordLockoutThreshold = Integer.parseInt(settings.getProperty("passwordLockoutThreshold", String.valueOf(DEFAULT_PASSWORD_LOCKOUT_THRESHOLD)));
            allowSpecialCharacters = Boolean.parseBoolean(settings.getProperty("allowSpecialCharacters", String.valueOf(DEFAULT_ALLOW_SPECIAL_CHARACTERS)));
            requireSpecialCharacters = Boolean.parseBoolean(settings.getProperty("requireSpecialCharacters", String.valueOf(DEFAULT_REQUIRE_SPECIAL_CHARACTERS)));
            requireNumeric = Boolean.parseBoolean(settings.getProperty("requireNumeric", String.valueOf(DEFAULT_REQUIRE_NUMERIC)));
            requireUppercase = Boolean.parseBoolean(settings.getProperty("requireUppercase", String.valueOf(DEFAULT_REQUIRE_UPPERCASE)));
            requireLowercase = Boolean.parseBoolean(settings.getProperty("requireLowercase", String.valueOf(DEFAULT_REQUIRE_LOWERCASE)));
            passwordComplexityLevel = Integer.parseInt(settings.getProperty("passwordComplexityLevel", String.valueOf(DEFAULT_PASSWORD_COMPLEXITY_LEVEL)));
            initLogger();
            LOGGER.info("Loaded settings from " + SETTINGS_FILE);
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "Could not load settings file", e);
        } catch (NumberFormatException e) {
            LOGGER.log(Level.WARNING, "Invalid loginAttempts setting, using default", e);
            loginAttempts = DEFAULT_LOGIN_ATTEMPTS;
        }
    }

    private static void initLogger() {
        if (loggerInitialized) {
            return;
        }

        try {
            FileHandler fileHandler = new FileHandler(logFile, true);
            fileHandler.setFormatter(new SimpleFormatter());
            LOGGER.addHandler(fileHandler);
            LOGGER.setLevel(Level.ALL);
            loggerInitialized = true;
        } catch (IOException e) {
            System.err.println("Could not initialize logger: " + e.getMessage());
        }
    }

    /**
     * Get the lockout end time for a username.
     * Returns 0 if the account is not locked or does not exist.
     */
    private static long getLockoutTime(String username) {
        try (BufferedReader reader = new BufferedReader(new FileReader(lockoutsFile))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.trim().isEmpty()) continue;
                String[] parts = line.split(",");
                if (parts.length == 2 && parts[0].equals(username)) {
                    try {
                        return Long.parseLong(parts[1]);
                    } catch (NumberFormatException e) {
                        LOGGER.log(Level.WARNING, "Invalid lockout time for user: " + username, e);
                        return 0;
                    }
                }
            }
        } catch (FileNotFoundException e) {
            // File doesn't exist yet, no lockouts
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "Could not read lockouts file", e);
        }
        return 0;
    }

    /**
     * Check if an account is currently locked out.
     */
    private static boolean isAccountLocked(String username) {
        long lockoutTime = getLockoutTime(username);
        if (lockoutTime > System.currentTimeMillis()) {
            if (lockoutTime == Long.MAX_VALUE) {
                out.println("Account is locked indefinitely.");
            } else {
                long minutesRemaining = (lockoutTime - System.currentTimeMillis()) / (1000 * 60);
                out.println("Account is locked. Try again in " + minutesRemaining + " minute(s).");
            }
            LOGGER.warning("Login attempt on locked account: " + username);
            return true;
        }
        return false;
    }

    /**
     * Lock an account until the specified time (in milliseconds).
     */
    private static void lockAccount(String username, long lockoutEndTime) {
        Map<String, Long> lockouts = new HashMap<>();
        loadLockedAccounts(lockouts);
        lockouts.put(username, lockoutEndTime);
        saveLockedAccounts(lockouts);

        String durationMessage;
        if (lockoutEndTime == Long.MAX_VALUE) {
            durationMessage = "indefinitely";
        } else {
            long minutesDuration = Math.max(0, (lockoutEndTime - System.currentTimeMillis()) / (1000 * 60));
            durationMessage = minutesDuration + " minute(s)";
        }

        LOGGER.info("Account locked: " + username + " for " + durationMessage);
        out.println("Account locked " + durationMessage + ".");
    }

    /**
     * Unlock an account immediately.
     */
    private static void unlockAccount(String username) {
        Map<String, Long> lockouts = new HashMap<>();
        loadLockedAccounts(lockouts);
        if (lockouts.remove(username) != null) {
            saveLockedAccounts(lockouts);
            LOGGER.info("Account unlocked: " + username);
            out.println("Account " + username + " has been unlocked.");
        } else {
            out.println("Account " + username + " was not locked.");
        }
    }

    /**
     * Load all locked accounts from the lockouts file into a Map.
     */
    private static void loadLockedAccounts(Map<String, Long> lockouts) {
        lockouts.clear();
        try (BufferedReader reader = new BufferedReader(new FileReader(lockoutsFile))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.trim().isEmpty()) continue;
                String[] parts = line.split(",");
                if (parts.length == 2) {
                    try {
                        String username = parts[0];
                        long lockoutTime = Long.parseLong(parts[1]);
                        // Only keep lockouts that haven't expired
                        if (lockoutTime > System.currentTimeMillis()) {
                            lockouts.put(username, lockoutTime);
                        }
                    } catch (NumberFormatException e) {
                        LOGGER.log(Level.WARNING, "Invalid lockout entry in file", e);
                    }
                }
            }
        } catch (FileNotFoundException e) {
            // File doesn't exist yet, which is fine
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "Could not read lockouts file", e);
        }
    }

    /**
     * Save locked accounts from Map to the lockouts file.
     */
    private static void saveLockedAccounts(Map<String, Long> lockouts) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(lockoutsFile))) {
            for (Map.Entry<String, Long> entry : lockouts.entrySet()) {
                // Only save lockouts that haven't expired
                if (entry.getValue() > System.currentTimeMillis()) {
                    writer.write(entry.getKey() + "," + entry.getValue());
                    writer.newLine();
                }
            }
            LOGGER.info("Saved " + lockouts.size() + " active lockouts to " + lockoutsFile);
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Could not save lockouts file", e);
        }
    }

    private static long calculateLockoutEndTime(long duration, TimeUnit unit) {
        if (duration <= 0) {
            return Long.MAX_VALUE;
        }
        return System.currentTimeMillis() + unit.toMillis(duration);
    }

    private static void copyDefaultSettings(File settingsFile) {
        try (InputStream input = LoginSystem.class.getResourceAsStream(SETTINGS_RESOURCE)) {
            if (input == null) {
                LOGGER.warning("Default settings resource not found: " + SETTINGS_RESOURCE);
                return;
            }
            Files.copy(input, settingsFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
            LOGGER.info("Copied default settings from resource to " + SETTINGS_FILE);
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Could not copy default settings to working folder", e);
        }
    }

    private static void saveSettings() {
        try (FileWriter writer = new FileWriter(SETTINGS_FILE)) {
            settings.store(writer, "Login system settings");
            LOGGER.info("Saved settings to " + SETTINGS_FILE);
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Could not save settings file", e);
        }
    }

    /**
     * Entry point for the login system application.
     * Repeatedly prompts for login, then shows the main menu until logout.
     */
    public static void main(String[] args) throws IOException {
        Map<String, String> accounts = new HashMap<>();
        List<String> admins = new ArrayList<>();

        loadSettings();
        loadAccountsFromCSV(accounts);
        loadAdminsFromTxt(admins);
        LOGGER.info("Login system initialized.");
        out.println(licenseBanner);

        out.println("Welcome to the access portal!");

        while (true) {
            String username = logIn(accounts, admins);
            saveAccountsToCSV(accounts);

            boolean isAdmin = admins.contains(username);
            out.println("Welcome to the console. Please choose an option to continue!");

            String choice;
            do {
                choice = showMenu(isAdmin);
                switch (choice) {
                    case "1" -> out.println("Logging out...");
                    case "2" -> {
                        createAccount(accounts, false, admins);
                        saveAccountsToCSV(accounts);
                    }
                    case "3" -> numberGuess();
                    case "4" -> {
                        if (isAdmin) {
                            adminPortal(accounts, admins);
                        } else {
                            out.println("Invalid option. Please try again.");
                        }
                    }
                    default -> out.println("Invalid option. Please try again.");
                }
            } while (!choice.equals("1"));

            LOGGER.info("User logged out: " + username);
            out.println("You have been logged out. Please log in again.");
        }
    }

    /**
     * Show the main menu and return the user's choice.
     * Admin users see an additional admin portal option.
     */
    private static String showMenu(boolean isAdmin) {
        if (isAdmin) {
            out.println("""
                    1: Logout
                    2: Create a new account
                    3: Guess a number
                    4: Enter Admin Portal
                    """);
        } else {
            out.println("""
                    1: Logout
                    2: Create a new account
                    3: Guess a number
                    """);
        }
        return readLine("Choose an option: ");
    }

    private static String showAdminMenu() {
        out.println("""
                1: Delete an account
                2: Promote user to admin
                3: Create an account
                4: Advanced settings
                5: Unlock/lock accounts
                6: Exit to menu
                """);
        return readLine("Choose an option: ");
    }

    /**
     * Display the admin portal and handle admin-specific actions.
     */
    private static void adminPortal(Map<String, String> accounts, List<String> admins) {
        String choice;
        do {
            choice = showAdminMenu();
            switch (choice) {
                case "1" -> deleteAccount(accounts, admins);
                case "2" -> promoteToAdmin(accounts, admins);
                case "3" -> createAPAccount(accounts, admins);
                case "4" -> showAdvancedSettings(accounts, admins);
                case "5" -> lockAccountMenu(accounts, admins);
                case "6" -> out.println("Returning to main menu...");
                default -> out.println("Invalid option. Please try again.");
            }
        } while (!choice.equals("6"));
    }
    /**
     * Display a menu to lock or unlock accounts
     * @param accounts
     * @param admins
     */

    private static void lockAccountMenu(Map<String, String> accounts, List<String> admins){
        out.println("""
                1: Return to menu
                2: Lock Account
                3: Unlock account
                """);
        String choice = readLine("Please choose an option: ");
        while(!choice.equals("1")){
            switch(choice){
                case "1" -> out.println("Exiting to menu...");
                case "2" -> displayLockAccount(accounts, admins);
                case "3" -> displayUnlockAccount(accounts, admins);
            }
            choice = readLine("Please choose an option: ");
        }
                
    }

    private static void displayLockAccount(Map<String, String> accounts, List<String> admins){
        out.println("All accounts: ");
        for (String username : accounts.keySet()) {
            out.println(username);
        }
        String username = readLine("Choose an account to lock: ");
        if (!accounts.containsKey(username)) {
            LOGGER.warning("Lock requested for missing account: " + username);
            out.println("That account does not exist.");
            return;
        }
        long lockTimeSeconds = readLong("Enter how long to lock the account for (0 for indefinite):", 0, 9999);
        long lockEndTime = calculateLockoutEndTime(lockTimeSeconds, TimeUnit.SECONDS);
        String lockDescription = lockTimeSeconds == 0 ? "indefinitely" : (lockTimeSeconds + " second(s)");

        if (!askYesNo("Are you sure you would like to lock account: " + username + " for " + lockDescription + "? (y/n)")) {
            out.println("Account lock abort");
            return;
        }
        lockAccount(username, lockEndTime);
        
        LOGGER.fine("Account " + username + " locked out for " + lockDescription + ".");
    }

    private static void displayUnlockAccount(Map<String, String> accounts, List<String> admins){
        HashMap<String, Long> locked = new HashMap<>();
        out.println("All locked accounts: ");
        loadLockedAccounts(locked);
        for(String username: locked.keySet()){
            out.println(username);
        }
        String unlocked = readLine("Enter the name of the account you wish to unlock: ");
        if(!askYesNo("Are you sure you would like to unlock " + unlocked + "? (y/n)")){
            out.println("Account unlocking aborted");
            return;
        }
        unlockAccount(unlocked);
        out.println("Account " + unlocked + " successfully unlocked!");
        
        LOGGER.fine("Account " + unlocked + " was unlocked by an admin.");
        
    }

    /**
     * Delete an account from memory and persistent storage.
     */
    private static void deleteAccount(Map<String, String> accounts, List<String> admins) {
        out.println("Current users:");
        accounts.keySet().forEach(user -> out.println("- " + user));

        String usernameToDelete = readLine("Enter the username of the account you want to delete: ");
        if (!accounts.containsKey(usernameToDelete)) {
            LOGGER.warning("Delete requested for missing account: " + usernameToDelete);
            out.println("That account does not exist.");
            return;
        }

        if (!askYesNo("Are you sure you want to delete this account? (y/n): ")) {
            out.println("Account deletion aborted");
            return;
        }

        boolean removed = deleteAccountFromCSV(usernameToDelete);
        if (removed) {
            accounts.remove(usernameToDelete);
            admins.remove(usernameToDelete);
            saveAdminToTxt(admins);
            LOGGER.info("Deleted account: " + usernameToDelete);
            out.println("Account deleted successfully.");
        } else {
            LOGGER.warning("Failed deletion attempt for account: " + usernameToDelete);
            out.println("Failed to delete account. Please try again.");
        }
    }

    private static void promoteToAdmin(Map<String, String> accounts, List<String> admins) {
        out.println("Current users available:");
        accounts.keySet().forEach(user -> out.println("- " + user));

        String username = readLine("Please enter the username of the user you would like to promote to admin: ");
        if (!accounts.containsKey(username)) {
            LOGGER.warning("Privilege escalation requested for missing account: " + username);
            out.println("That account does not exist.");
            return;
        }

        if (!askYesNo("Are you sure you would like to escalate privileges for " + username + "? (y/n): ")) {
            out.println("Privilege escalation aborted");
            return;
        }

        if (!admins.contains(username)) {
            admins.add(username);
            saveAdminToTxt(admins);
            LOGGER.info("Promoted user to admin: " + username);
            out.println("Privilege escalation successful.");
        } else {
            out.println("User is already an admin.");
        }
    }

    /**
     * Provide sensitive admin settings behind an additional admin login.
     */
    private static void showAdvancedSettings(Map<String, String> accounts, List<String> admins) {
        out.println("You will have to log in again as you are accessing sensitive settings...");

        int attempts = 0;
        boolean isAdmin = false;

        while (!isAdmin) {
            String username = logIn(accounts, admins);
            isAdmin = admins.contains(username);
            if (!isAdmin) {
                attempts++;
                if (attempts >= loginAttempts) {
                    out.println("Max attempts reached. Exiting...");
                    System.exit(0);
                }
                out.println("Account not an admin!");
                out.println((loginAttempts - attempts) + " attempts remaining.");
            }
        }

        String choice;
        do {
            out.println("""
                    1: Exit to Admin Menu
                    2: Change Max Login Attempts
                    3: Flush System Data (WARNING)
                    4: Password Settings
                    """);
            choice = readLine("Choose an option: ");
            switch (choice) {
                case "1" -> out.println("Exiting advanced settings...");
                case "2" -> changeMaxLoginAttempts();
                case "3" -> flushSystemData(accounts, admins);
                case "4" -> showPasswordSettings();
                default -> out.println("Invalid option. Please try again.");
            }
        } while (!choice.equals("1"));
    }

    /**
     * Password settings submenu for managing password policies.
     */
    private static void showPasswordSettings() {
        String choice;
        do {
            out.println("""
                    1: Back to Advanced Settings
                    2: View Current Settings
                    3: Change Password Length Requirement
                    4: Change Min Uppercase Letters
                    5: Change Min Lowercase Letters
                    6: Change Min Numbers Required
                    7: Change Min Special Characters
                    8: Change Complexity Level (0-5)
                    9: Enable/Disable Password Strength
                    10: Password Lockout Settings
                    11: Special Character Options
                    """);
            choice = readLine("Choose an option: ");
            switch (choice) {
                case "1" -> out.println("Returning to Advanced Settings...");
                case "2" -> viewPasswordSettings();
                case "3" -> changeMinLength();
                case "4" -> changeMinUppercase();
                case "5" -> changeMinLowercase();
                case "6" -> changeMinNumbers();
                case "7" -> changeMinSpecialChars();
                case "8" -> changeComplexityLevel();
                case "9" -> togglePasswordStrength();
                case "10" -> showPasswordLockoutMenu();
                case "11" -> showSpecialCharacterMenu();
                default -> out.println("Invalid option. Please try again.");
            }
        } while (!choice.equals("1"));
    }

    private static void viewPasswordSettings() {
        out.println("""
                --- Current Password Settings ---
                Strength Enabled: """ + passwordEnabled + """
                Minimum Length: """ + minLength + """
                Min Uppercase: """ + minUppercase + """
                Min Lowercase: """ + minLowercase + """
                Min Numbers: """ + minNumbers + """
                Min Special Chars: """ + minSymbols + """
                Complexity Level: """ + passwordComplexityLevel + """
                Lockout Duration (min): """ + passwordLockoutDurationMinutes + """
                Lockout Threshold: """ + passwordLockoutThreshold + """
                Allow Special Chars: """ + allowSpecialCharacters + """
                Require Special Chars: """ + requireSpecialCharacters + """
                Require Numeric: """ + requireNumeric + """
                Require Uppercase: """ + requireUppercase + """
                Require Lowercase: """ + requireLowercase + """
                """);
    }

    private static void changeMinLength() {
        int value = readInt("Enter minimum password length (4-32): ", 4, 32);
        minLength = value;
        settings.setProperty("minLength", String.valueOf(minLength));
        saveSettings();
        LOGGER.info("Min password length changed to " + minLength);
        out.println("Minimum password length set to " + minLength);
    }

    private static void changeMinUppercase() {
        int value = readInt("Enter minimum uppercase letters required (0-10): ", 0, 10);
        minUppercase = value;
        settings.setProperty("minUppercase", String.valueOf(minUppercase));
        saveSettings();
        LOGGER.info("Min uppercase letters changed to " + minUppercase);
        out.println("Minimum uppercase letters set to " + minUppercase);
    }

    private static void changeMinLowercase() {
        int value = readInt("Enter minimum lowercase letters required (0-10): ", 0, 10);
        minLowercase = value;
        settings.setProperty("minLowercase", String.valueOf(minLowercase));
        saveSettings();
        LOGGER.info("Min lowercase letters changed to " + minLowercase);
        out.println("Minimum lowercase letters set to " + minLowercase);
    }

    private static void changeMinNumbers() {
        int value = readInt("Enter minimum numbers required (0-10): ", 0, 10);
        minNumbers = value;
        settings.setProperty("minNumbers", String.valueOf(minNumbers));
        saveSettings();
        LOGGER.info("Min numbers changed to " + minNumbers);
        out.println("Minimum numbers set to " + minNumbers);
    }

    private static void changeMinSpecialChars() {
        int value = readInt("Enter minimum special characters required (0-10): ", 0, 10);
        minSymbols = value;
        settings.setProperty("minSymbols", String.valueOf(minSymbols));
        saveSettings();
        LOGGER.info("Min special characters changed to " + minSymbols);
        out.println("Minimum special characters set to " + minSymbols);
    }

    private static void changeComplexityLevel() {
        out.println("""
                Complexity Levels:
                0: No requirements (just length)
                1: Length only
                2: Length + uppercase + lowercase (default)
                3: Level 2 + at least one number
                4: Level 3 + at least one special character
                5: All character types with higher minimums
                """);
        int value = readInt("Enter complexity level (0-5): ", 0, 5);
        passwordComplexityLevel = value;
        settings.setProperty("passwordComplexityLevel", String.valueOf(passwordComplexityLevel));
        saveSettings();
        LOGGER.info("Complexity level changed to " + passwordComplexityLevel);
        out.println("Complexity level set to " + passwordComplexityLevel);
    }

    private static void togglePasswordStrength() {
        passwordEnabled = !passwordEnabled;
        settings.setProperty("strengthRequirementsEnabled", String.valueOf(passwordEnabled));
        saveSettings();
        LOGGER.info("Password strength requirements " + (passwordEnabled ? "enabled" : "disabled"));
        out.println("Password strength requirements " + (passwordEnabled ? "enabled" : "disabled"));
    }

    private static void showPasswordLockoutMenu() {
        String choice;
        do {
            out.println("""
                    1: Back to Password Settings
                    2: Change Lockout Duration (minutes)
                    3: Change Lockout Threshold (attempts)
                    """);
            choice = readLine("Choose an option: ");
            switch (choice) {
                case "1" -> out.println("Returning to Password Settings...");
                case "2" -> changePasswordLockoutDuration();
                case "3" -> changePasswordLockoutThreshold();
                default -> out.println("Invalid option. Please try again.");
            }
        } while (!choice.equals("1"));
    }

    private static void changePasswordLockoutDuration() {
        int value = readInt("Enter lockout duration in minutes (1-60): ", 1, 60);
        passwordLockoutDurationMinutes = value;
        settings.setProperty("passwordLockoutDurationMinutes", String.valueOf(passwordLockoutDurationMinutes));
        saveSettings();
        LOGGER.info("Lockout duration changed to " + passwordLockoutDurationMinutes);
        out.println("Lockout duration set to " + passwordLockoutDurationMinutes + " minutes");
    }

    private static void changePasswordLockoutThreshold() {
        int value = readInt("Enter lockout threshold (failed attempts before lockout, 1-20): ", 1, 20);
        passwordLockoutThreshold = value;
        settings.setProperty("passwordLockoutThreshold", String.valueOf(passwordLockoutThreshold));
        saveSettings();
        LOGGER.info("Lockout threshold changed to " + passwordLockoutThreshold);
        out.println("Lockout threshold set to " + passwordLockoutThreshold + " attempts");
    }

    private static void showSpecialCharacterMenu() {
        String choice;
        do {
            out.println("""
                    1: Back to Password Settings
                    2: Toggle Allow Special Characters
                    3: Toggle Require Special Characters
                    4: Toggle Require Numeric
                    5: Toggle Require Uppercase
                    6: Toggle Require Lowercase
                    """);
            choice = readLine("Choose an option: ");
            switch (choice) {
                case "1" -> out.println("Returning to Password Settings...");
                case "2" -> toggleAllowSpecialCharacters();
                case "3" -> toggleRequireSpecialCharacters();
                case "4" -> toggleRequireNumeric();
                case "5" -> toggleRequireUppercase();
                case "6" -> toggleRequireLowercase();
                default -> out.println("Invalid option. Please try again.");
            }
        } while (!choice.equals("1"));
    }

    private static void toggleAllowSpecialCharacters() {
        allowSpecialCharacters = !allowSpecialCharacters;
        settings.setProperty("allowSpecialCharacters", String.valueOf(allowSpecialCharacters));
        saveSettings();
        LOGGER.info("Allow special characters " + (allowSpecialCharacters ? "enabled" : "disabled"));
        out.println("Special characters " + (allowSpecialCharacters ? "now allowed" : "no longer allowed"));
    }

    private static void toggleRequireSpecialCharacters() {
        requireSpecialCharacters = !requireSpecialCharacters;
        settings.setProperty("requireSpecialCharacters", String.valueOf(requireSpecialCharacters));
        saveSettings();
        LOGGER.info("Require special characters " + (requireSpecialCharacters ? "enabled" : "disabled"));
        out.println("Special characters " + (requireSpecialCharacters ? "now required" : "no longer required"));
    }

    private static void toggleRequireNumeric() {
        requireNumeric = !requireNumeric;
        settings.setProperty("requireNumeric", String.valueOf(requireNumeric));
        saveSettings();
        LOGGER.info("Require numeric " + (requireNumeric ? "enabled" : "disabled"));
        out.println("Numeric characters " + (requireNumeric ? "now required" : "no longer required"));
    }

    private static void toggleRequireUppercase() {
        requireUppercase = !requireUppercase;
        settings.setProperty("requireUppercase", String.valueOf(requireUppercase));
        saveSettings();
        LOGGER.info("Require uppercase " + (requireUppercase ? "enabled" : "disabled"));
        out.println("Uppercase characters " + (requireUppercase ? "now required" : "no longer required"));
    }

    private static void toggleRequireLowercase() {
        requireLowercase = !requireLowercase;
        settings.setProperty("requireLowercase", String.valueOf(requireLowercase));
        saveSettings();
        LOGGER.info("Require lowercase " + (requireLowercase ? "enabled" : "disabled"));
        out.println("Lowercase characters " + (requireLowercase ? "now required" : "no longer required"));
    }

    private static void changeMaxLoginAttempts() {
        int tempAttempts = readInt("Enter what you would like the new max login attempts to be: ", 1, 99);
        loginAttempts = tempAttempts;
        settings.setProperty("loginAttempts", String.valueOf(loginAttempts));
        saveSettings();
        LOGGER.info("Max login attempts changed to " + loginAttempts);
        out.println("Set max login attempts to " + loginAttempts);
    }

    private static void flushSystemData(Map<String, String> accounts, List<String> admins) {
        out.println("Please login again to confirm this operation...");

        int attempts = 0;
        boolean isAdmin = false;
        while (!isAdmin) {
            String username = logIn(accounts, admins);
            isAdmin = admins.contains(username);
            if (!isAdmin) {
                attempts++;
                if (attempts >= loginAttempts) {
                    out.println("Max attempts reached. Exiting...");
                    System.exit(0);
                }
                out.println("Account not an admin!");
                out.println((loginAttempts - attempts) + " attempts remaining.");
            }
        }

        if (!askYesNo("This operation will delete ALL data, are you sure you would like to continue? (y/n): ")) {
            out.println("Data deletion aborted");
            return;
        }

        if (new File(accountsFile).delete() && new File(adminsFile).delete() && new File(SETTINGS_FILE).delete() && new File(logFile).delete() && new File(lockoutsFile).delete()) {
            accounts.clear();
            admins.clear();
            LOGGER.warning("All data flushed by admin.");
            out.println("Successfully deleted all data, exiting...");
        } else {
            LOGGER.severe("Error occurred while deleting system data.");
            out.println("Error occurred while deleting data.");
        }
        System.exit(0);
    }

    /**
     * Hash a password using SHA-256 and return the hex digest.
     */
    private static String hashPassword(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(password.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * Authenticate a user by username and password.
     * This method returns the logged-in username on success.
     */
    private static String logIn(Map<String, String> accounts, List<String> admins) {
        if (accounts.isEmpty()) {
            LOGGER.info("No accounts found, creating initial admin account.");
            out.println("Please create an account.");
            createAccount(accounts, true, admins);
            out.println("You will now have to log in.");
            saveAccountsToCSV(accounts);
        }
        String tempUsr = "";

        int attempts = 0;
        while (attempts < loginAttempts) {
            out.println("Please log in");
            tempUsr = readLine("Username: ");
            if(isAccountLocked(tempUsr)){
                out.print("This account is currently locked. Please wait or contact an admin to get it unlocked.");
                System.exit(0);
            }
            String tempPass = readLine("Password: ");
            String hashedTempPass = hashPassword(tempPass);

            if (accounts.containsKey(tempUsr) && accounts.get(tempUsr).equals(hashedTempPass)) {
                LOGGER.info("User logged in: " + tempUsr);
                out.println("Successfully logged in!");
                return tempUsr;
            }

            LOGGER.warning("Invalid login attempt for user: " + tempUsr);
            attempts++;
            int remaining = loginAttempts - attempts;
            out.println("Incorrect username or password");
            out.println("You have " + remaining + " attempts remaining.");
        }

        out.println("You have no attempts remaining. Account locked, please ask an admin to unlock it, or wait the lockout time.");
        long lockoutTime = calculateLockoutEndTime(passwordLockoutDurationMinutes, TimeUnit.MINUTES);
        lockAccount(tempUsr, lockoutTime);
        System.exit(0);
        return ""; // unreachable, but required by Java
    }

    /**
     * Prompt for and create a new user account.
     */
    private static void createAccount(Map<String, String> accounts, boolean admin, List<String> admins) {
        while (true) {
            String tempUsr = readLine("Please enter the new account's username: ");
            if (tempUsr.isEmpty()) {
                out.println("Username cannot be empty.");
                continue;
            }
            if (accounts.containsKey(tempUsr)) {
                out.println("Username already exists. Choose another.");
                continue;
            }

            String tempPass = readLine("Please enter the new account's password: ");
            if (tempPass.isEmpty()) {
                out.println("Password cannot be empty.");
                continue;
            }
            if(passwordEnabled){
                while(!validatePassword(tempPass)){
                tempPass = readLine("Please enter the new account's password: ");
                if(!validatePassword(tempPass)){
                    out.printf("""
                            Password invalid, it must:
                            Be at least %d characters long.
                            Contain %d numbers.
                            Contain %d symbols.
                    """, minLength, minNumbers, minSymbols);
                }
            }
            }

            String hashedPass = hashPassword(tempPass);
            accounts.put(tempUsr, hashedPass);
            if (admin) {
                admins.add(tempUsr);
                saveAdminToTxt(admins);
            }
            LOGGER.info("Created account: " + tempUsr + (admin ? " (admin)" : ""));
            out.println(admin ? "Admin account created successfully!" : "Account created successfully!");
            break;
        }
    }

    /**
     * Allow an admin to create a new account and optionally promote it. ( Admins do not have to meet password requirements )
     */
    private static void createAPAccount(Map<String, String> accounts, List<String> admins) {
        while (true) {
            String tempUsr = readLine("Enter the username of the user you would like to create: ");
            if (tempUsr.isEmpty()) {
                out.println("Username cannot be empty.");
                continue;
            }
            if (accounts.containsKey(tempUsr)) {
                out.println("Username already exists. Choose another.");
                continue;
            }

            String tempPass = readLine("Enter the password of the user you would like to create: ");
            if (tempPass.isEmpty()) {
                out.println("Password cannot be empty.");
                continue;
            }

            boolean admin = askYesNo("Do you want them to be an admin? (y/n): ");
            String hashedPass = hashPassword(tempPass);
            accounts.put(tempUsr, hashedPass);
            if (admin) {
                admins.add(tempUsr);
                saveAdminToTxt(admins);
            }
            saveAccountsToCSV(accounts);
            LOGGER.info("Created account: " + tempUsr + (admin ? " (admin)" : "" + " via admin portal"));
            out.println("Account created successfully");
            break;
        }
    }

    /**
     * Simple number guessing game for authenticated users.
     */
    private static void numberGuess() {
        Random rg = new Random();
        int randomNum = rg.nextInt(10) + 1; // 1-10
        int guesses = 0;

        out.println("Try to guess a random number from 1-10!");
        int guess;
        do {
            guess = readInt("Your guess: ", 1, 10);
            if (guess != randomNum) {
                out.println("Incorrect!");
                guesses++;
            }
        } while (guess != randomNum);

        out.println("You are correct after " + guesses + " guesses!");
    }

    private static String escapeCSVField(String field) {
        if (field.contains(",") || field.contains("\"") || field.contains("\n")) {
            return '"' + field.replace("\"", "\"\"") + '"';
        }
        return field;
    }

    /**
     * Parse one CSV line and return quoted fields correctly.
     */
    private static String[] parseCSVLine(String line) {
        List<String> fields = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean inQuotes = false;

        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '"') {
                if (inQuotes && i + 1 < line.length() && line.charAt(i + 1) == '"') {
                    current.append('"');
                    i++; // skip escaped quote
                } else {
                    inQuotes = !inQuotes;
                }
            } else if (c == ',' && !inQuotes) {
                fields.add(current.toString());
                current.setLength(0);
            } else {
                current.append(c);
            }
        }
        fields.add(current.toString());
        return fields.toArray(new String[0]);
    }

    /**
     * Persist account map to a CSV file.
     */
    private static void saveAccountsToCSV(Map<String, String> accounts) {
        try (FileWriter writer = new FileWriter(accountsFile)) {
            writer.write(CSV_HEADER + "\n");
            for (Map.Entry<String, String> entry : accounts.entrySet()) {
                String username = escapeCSVField(entry.getKey());
                String password = escapeCSVField(entry.getValue());
                writer.write(username + "," + password + "\n");
            }
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error saving accounts to CSV", e);
            out.println("Error saving accounts to CSV: " + e.getMessage());
        }
    }

    private static void saveAdminToTxt(List<String> admins) {
        try (FileWriter writer = new FileWriter(adminsFile)) {
            for (String admin : admins) {
                writer.write(admin + "\n");
            }
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error occurred while saving admins", e);
            out.println("Error occurred while saving admins: " + e.getMessage());
        }
    }

    private static void loadAdminsFromTxt(List<String> admins) {
        File file = new File(adminsFile);
        if (!file.exists()) {
            try {
                file.createNewFile();
            } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Failed to initialize " + adminsFile, e);
            }
            return;
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.trim().isEmpty()) {
                    continue;
                }
                admins.add(line.trim());
            }
            LOGGER.info("Loaded admins successfully.");
            out.println("Loaded admins successfully!");
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error occurred while loading admins from file", e);
            out.println("Error occurred while loading admins from file: " + e.getMessage());
        }
    }

    private static boolean deleteAccountFromCSV(String username) {
        File tempFile = new File(accountsFile + ".tmp");
        boolean removed = false;

        try (BufferedReader reader = new BufferedReader(new FileReader(accountsFile));
             BufferedWriter writer = new BufferedWriter(new FileWriter(tempFile))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.trim().isEmpty()) {
                    continue;
                }
                if (line.equals(CSV_HEADER)) {
                    writer.write(line);
                    writer.newLine();
                    continue;
                }
                String[] parts = parseCSVLine(line);
                if (parts.length == 2 && parts[0].equals(username)) {
                    removed = true;
                    continue;
                }
                writer.write(line);
                writer.newLine();
            }
        } catch (FileNotFoundException e) {
            out.println("Accounts file not found.");
            return false;
        } catch (IOException e) {
            out.println("Error deleting account from CSV: " + e.getMessage());
            return false;
        }

        File originalFile = new File(accountsFile);
        return removed && tempFile.renameTo(originalFile);
    }

    /**
     * Load accounts from CSV into memory.
     */
    private static void loadAccountsFromCSV(Map<String, String> accounts) {
        File file = new File(accountsFile);
        if (!file.exists()) {
            LOGGER.info("No accounts file found. Starting with empty accounts.");
            out.println("No existing CSV file found. Starting with empty accounts.");
            return;
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            boolean firstLine = true;
            while ((line = reader.readLine()) != null) {
                if (line.trim().isEmpty()) {
                    continue;
                }
                if (firstLine) {
                    firstLine = false;
                    continue;
                }
                String[] parts = parseCSVLine(line);
                if (parts.length == 2) {
                    accounts.put(parts[0].trim(), parts[1].trim());
                }
            }
            out.println("Accounts loaded from CSV file successfully!");
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error loading accounts from CSV", e);
            out.println("Error loading accounts from CSV: " + e.getMessage());
        }
    }

    private static String readLine(String prompt) {
        out.print(prompt);
        return keyboard.nextLine().trim();
    }

    private static int readInt(String prompt, int min, int max) {
        while (true) {
            String input = readLine(prompt);
            try {
                int value = Integer.parseInt(input);
                if (value < min || value > max) {
                    out.println("Please enter a number between " + min + " and " + max + ".");
                    continue;
                }
                return value;
            } catch (NumberFormatException e) {
                out.println("Please enter a valid number.");
            }
        }
    }

    private static long readLong(String prompt, long min, long max) {
        while (true) {
            String input = readLine(prompt);
            try {
                long value = Long.parseLong(input);
                if (value < min || value > max) {
                    out.println("Please enter a number between " + min + " and " + max + ".");
                    continue;
                }
                return value;
            } catch (NumberFormatException e) {
                out.println("Please enter a valid number.");
            }
        }
    }

    private static boolean askYesNo(String prompt) {
        while (true) {
            String input = readLine(prompt);
            if (input.equalsIgnoreCase("y") || input.equalsIgnoreCase("yes")) {
                return true;
            }
            if (input.equalsIgnoreCase("n") || input.equalsIgnoreCase("no")) {
                return false;
            }
            out.println("Invalid input. Please enter 'y' or 'n'.");
        }
    }

    private static boolean validatePassword(String password) {
        if (password == null || !passwordEnabled) {
            return password != null && password.length() > 0;
        }

        // Count character types
        long digitCount = password.chars().filter(Character::isDigit).count();
        long symbolCount = password.chars().filter(ch -> !Character.isLetterOrDigit(ch)).count();
        long uppercaseCount = password.chars().filter(Character::isUpperCase).count();
        long lowercaseCount = password.chars().filter(Character::isLowerCase).count();

        // Basic length check
        if (password.length() < minLength) {
            out.println("Password must be at least " + minLength + " characters long.");
            return false;
        }

        // Uppercase requirement
        if (uppercaseCount < minUppercase) {
            out.println("Password must contain at least " + minUppercase + " uppercase letter(s).");
            return false;
        }

        // Lowercase requirement
        if (lowercaseCount < minLowercase) {
            out.println("Password must contain at least " + minLowercase + " lowercase letter(s).");
            return false;
        }

        // Numeric requirement
        if (digitCount < minNumbers) {
            out.println("Password must contain at least " + minNumbers + " number(s).");
            return false;
        }

        if (requireNumeric && digitCount == 0) {
            out.println("Password must contain at least one number.");
            return false;
        }

        // Special character checks
        if (symbolCount < minSymbols) {
            out.println("Password must contain at least " + minSymbols + " special character(s).");
            return false;
        }

        if (requireSpecialCharacters && symbolCount == 0) {
            out.println("Password must contain at least one special character.");
            return false;
        }

        // Check if special characters are allowed
        if (!allowSpecialCharacters && symbolCount > 0) {
            out.println("Password cannot contain special characters.");
            return false;
        }

        // Check uppercase requirement
        if (requireUppercase && uppercaseCount == 0) {
            out.println("Password must contain at least one uppercase letter.");
            return false;
        }

        // Check lowercase requirement
        if (requireLowercase && lowercaseCount == 0) {
            out.println("Password must contain at least one lowercase letter.");
            return false;
        }

        // Complexity level validation (0-5 scale)
        // Level 0: No requirements (just length)
        // Level 1: Length only
        // Level 2: Length + uppercase + lowercase (default)
        // Level 3: Level 2 + numbers
        // Level 4: Level 3 + special characters
        // Level 5: All character types required with higher minimums
        if (passwordComplexityLevel >= 3 && digitCount == 0) {
            out.println("Password complexity level " + passwordComplexityLevel + " requires at least one number.");
            return false;
        }

        if (passwordComplexityLevel >= 4 && symbolCount == 0) {
            out.println("Password complexity level " + passwordComplexityLevel + " requires at least one special character.");
            return false;
        }

        if (passwordComplexityLevel == 5 && (digitCount < 2 || symbolCount < 2 || uppercaseCount < 2 || lowercaseCount < 2)) {
            out.println("Password complexity level 5 requires at least 2 of each character type (uppercase, lowercase, numbers, special characters).");
            return false;
        }

        return true;
    }

}

