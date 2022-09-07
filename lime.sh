
###
#  lime.sh
###

# This script is used to wrap the compilation and execution of the lime binary.
# It requires that the wifi-coconut software has been installed and is a part of the path

wifi_coconut --wait --no-display --pcap=- | cargo run 