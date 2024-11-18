import Domain_scan
from pyfiglet import Figlet
import argparse
import sys

def main():
    figlet = Figlet(font='slant')
    print(figlet.renderText('CrawlNinja'))

    parser = argparse.ArgumentParser(
        description="Command-line vulnerability scanner tool. "
                    "Crawls a target website, scans forms, and checks for XSS vulnerabilities.",
        epilog="Example:\n"
               "  python your_script.py -t http://example.com \\\n"
               "  --ignore http://example.com/logout \\\n"
               "  --login http://example.com/login \\\n"
               "  --username testuser --password testpass",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument("-t", "--target", required=True, 
                        help="Target URL to scan, e.g., http://example.com")
    parser.add_argument("-i", "--ignore", 
                        help="URL to ignore during scanning, e.g., http://example.com/logout")
    parser.add_argument("-l", "--login", 
                        help="Login URL for the target site, e.g., http://example.com/login")
    parser.add_argument("-u", "--username", 
                        help="Username for login, e.g., testuser")
    parser.add_argument("-p", "--password", 
                        help="Password for login, e.g., testpass")
    parser.add_argument("-c", "--choice", 
                        help="Type 0 for just finding URL from website 1 for xss 2 for sql")
    parser.add_argument("-s", "--subdomains", action="store_true",
                        help="Enable subdomain discovery with Subfinder")
    parser.add_argument("-o", "--output", 
                        help="Specify output file to save the results, e.g., output.txt")

    args = parser.parse_args()

    # Check if login arguments are provided without username or password
    if args.login and (not args.username or not args.password):
        parser.error("--login requires --username and --password")

    # Prepare login info
    login_info = None
    if args.login:
        login_info = {
            "username": args.username,
            "password": args.password,
            "Login": "submit"
        }

    # Initialize scanner with target and optional ignore URL
    try:
        scan = Domain_scan.Scanner(args.target, args.ignore, args.choice, args.output)
    except Exception as e:
        print(f"Error initializing scanner: {e}")
        sys.exit(1)

    # Attempt login if login_info is provided
    if login_info:
        try:
            response = scan.session.post(args.login, data=login_info)
            response.raise_for_status()
            print(f"Logged in successfully to {args.login}")
        except Exception as e:
            print(f"Failed to log in: {e}")
            sys.exit(1)

    try:
        if args.subdomains:
            scan.discover_subdomains()
        else:
            scan.crawl()
        if args.choice != 0:
            scan.run_scanner()
    except Exception as e:
        print(f"Error during scanning: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
