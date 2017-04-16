import socket, sys
from struct import *
from thread import *
#Convert a string of 6 characters of ethernet address into a dash separated hex string

import json

class Ruleset(object):
	"""docstring for Ruleset"""
	data = {}
	def __init__(self, arg):
		self.data = arg
	def add(self,type,value):
		if value == 1 or value == 2 or value == 3:
			add = raw_input("enter a valid address to block:")
			if type == 1:
				if value == 1:
					self.data["Inbound"]["MAC"].append(add)
				if value == 2:
					self.data["Inbound"]["IPv4"].append(add)
				if value == 3:
					self.data["Inbound"]["IPv6"].append(add)
			else :
				if value == 1:
					self.data["Outbound"]["MAC"].append(add)
				if value == 2:
					self.data["Outbound"]["IPv4"].append(add)
				if value == 3:
					self.data["Outbound"]["IPv6"].append(add)
		elif value == 4 or value == 5 or value == 6:
			add = input("Enter a port number:")
			pre = input("Rule type 1. < , 2. = or 3.> 4. range  (equals or greater or less or as a part of range) rule?")
			pre -= 2
			if pre == 2:
				pre = input("Enter second Port:")
				add2 = pre
				pre = add
				add = add2
			if type == 1:
				if value == 4:
					self.data["Inbound"]["ICMP"].append((int(pre),int(add)))
				if value == 5:
					self.data["Inbound"]["TCP"].append((int(pre),int(add)))
				if value == 6:
					self.data["Inbound"]["UDP"].append((int(pre),int(add)))
			else :
				if value == 4:
					self.data["Outbound"]["ICMP"].append((int(pre),int(add)))
				if value == 5:
					self.data["Outbound"]["TCP"].append((int(pre),int(add)))
				if value == 6:
					self.data["Outbound"]["UDP"].append((int(pre),int(add)))

	def delete(self,type,value):
		v1,v2 = "",""
		if type == 1:
			v1 = "Inbound"
		else:
			v1 = "Outbound"
		if value == 1:
			v2 = "MAC"
		elif value == 2:
			v2 = "IPv4"
		elif value == 3:
			v2 = "IPv6"
		elif value == 4:
			v2 = "ICMP"
		elif value == 5:
			v2 = "TCP"
		else:
			v2 = "UDP"

		print "Rule Id's:"
		for x in xrange(0,len(self.data[v1][v2])):
			print x,self.data[v1][v2][x]
			pass

		id_s = input("Enter the ruleid to delete:")
		while id_s<0 or id_s>(len(self.data[v1][v2])-1):
			id_s = input("Enter the Correct ruleid to delete:")
		self.data[v1][v2].pop(id_s)
		print "deletion successfull"
		pass
	def update(self,type,value):
		v1,v2 = "",""
		if type == 1:
			v1 = "Inbound"
		else:
			v1 = "Outbound"
		if value == 1:
			v2 = "MAC"
		elif value == 2:
			v2 = "IPv4"
		elif value == 3:
			v2 = "IPv6"
		elif value == 4:
			v2 = "ICMP"
		elif value == 5:
			v2 = "TCP"
		else:
			v2 = "UDP"

		print "Rule Id's:"
		for x in xrange(0,len(self.data[v1][v2])):
			print x,self.data[v1][v2][x]
			pass

		id_s = input("Enter the ruleid to Update:")
		while id_s<0 or id_s>(len(self.data[v1][v2])-1):
			id_s = input("Enter the Correct ruleid to update:")

		if value == 1 or value == 2 or value == 3:
			add = raw_input("enter a valid address to update:")
			if type == 1:
				if value == 1:
					self.data["Inbound"]["MAC"][id_s] = add
				if value == 2:
					self.data["Inbound"]["IPv4"][id_s] = add
				if value == 3:
					self.data["Inbound"]["IPv6"][id_s] = add
			else :
				if value == 1:
					self.data["Outbound"]["MAC"][id_s] = add
				if value == 2:
					self.data["Outbound"]["IPv4"][id_s] = add
				if value == 3:
					self.data["Outbound"]["IPv6"][id_s] = add
		elif value == 4 or value == 5 or value == 6:
			add = input("Enter a port number:")
			pre = input("Rule type 1. < , 2. = or 3.> 4. range  (equals or greater or less or as a part of range) rule?")
			pre -= 2
			if pre == 2:
				pre = input("Enter second Port:")
				add2 = pre
				pre = add
				add = add2
			if type == 1:
				if value == 4:
					self.data["Inbound"]["ICMP"][id_s] = (int(pre),int(add))
				if value == 5:
					self.data["Inbound"]["TCP"][id_s] = (int(pre),int(add))
				if value == 6:
					self.data["Inbound"]["UDP"][id_s] = (int(pre),int(add))
			else :
				if value == 4:
					self.data["Outbound"]["ICMP"][id_s] = (int(pre),int(add))
				if value == 5:
					self.data["Outbound"]["TCP"][id_s] = (int(pre),int(add))
				if value == 6:
					self.data["Outbound"]["UDP"][id_s] = (int(pre),int(add))

		print "Updation Successful"
		pass

	def stats(self):
		print(json.dumps(self.data, indent = 4))
		pass

	def verify(self,macAdd,bool_IPv4,IPv4,bool_IPv6,IPv6,bool_ICMP,ICMPPort,bool_TCP,TCPPort,bool_UDP,UDPPort,bool_Inbound,bool_outbound):
		if bool_Inbound:
			if macAdd in self.data["Inbound"]["MAC"]:
				print "Packet Rejected as MacAdd failed"
				return False
			if bool_IPv4:
				if IPv4 in self.data["Inbound"]["IPv4"]:
					print "Packet Rejected as IPv4 failed"
					return False
			if bool_IPv6:
				if IPv6 in self.data["Inbound"]["IPv6"]:
					print "Packet Rejected as IPv6 failed"
					return False
			if bool_ICMP:
				for i in range(0,len(self.data["Inbound"]["ICMP"])):
					if self.data["Inbound"]["ICMP"][i][0] == -1:
						if ICMPPort<self.data["Inbound"]["ICMP"][i][1]:
							print "Packet Rejected as ICMP failed rule number, ",i," in ICMP inbound rules"
							return False
					elif self.data["Inbound"]["ICMP"][i][0] == 0:
						if ICMPPort == self.data["Inbound"]["ICMP"][i][1]:
							print "Packet Rejected as ICMP failed rule number, ",i," in ICMP inbound rules"
							return False
					elif self.data["Inbound"]["ICMP"][i][0] == 1:
						if ICMPPort>self.data["Inbound"]["ICMP"][i][1]:
							print "Packet Rejected as ICMP failed rule number, ",i," in ICMP inbound rules"
							return False
					else :
						if ICMPPort>self.data["Inbound"]["ICMP"][i][0] and ICMPPort<self.data["Inbound"]["ICMP"][i][1]:
							print "Packet Rejected as ICMP failed rule number, ",i," in ICMP inbound rules"
							return False
			if bool_TCP:
				for i in range(0,len(self.data["Inbound"]["TCP"])):
					if self.data["Inbound"]["TCP"][i][0] == -1:
						if TCPPort<self.data["Inbound"]["TCP"][i][1]:
							print "Packet Rejected as TCP failed rule number, ",i," in TCP inbound rules"
							return False
					elif self.data["Inbound"]["TCP"][i][0] == 0:
						if TCPPort == self.data["Inbound"]["TCP"][i][1]:
							print "Packet Rejected as TCP failed rule number, ",i," in TCP inbound rules"
							return False
					elif self.data["Inbound"]["TCP"][i][0] == 1:
						if TCPPort>self.data["Inbound"]["TCP"][i][1]:
							print "Packet Rejected as TCP failed rule number, ",i," in TCP inbound rules"
							return False
					else :
						if TCPPort>self.data["Inbound"]["TCP"][i][0] and TCPPort<self.data["Inbound"]["TCP"][i][1]:
							print "Packet Rejected as TCP failed rule number, ",i," in TCP inbound rules"
							return False
			if bool_UDP:
				for i in range(0,len(self.data["Inbound"]["UDP"])):
					if self.data["Inbound"]["UDP"][i][0] == -1:
						if UDPPort<self.data["Inbound"]["UDP"][i][1]:
							print "Packet Rejected as UDP failed rule number, ",i," in UDP inbound rules"
							return False
					elif self.data["Inbound"]["UDP"][i][0] == 0:
						if UDPPort == self.data["Inbound"]["UDP"][i][1]:
							print "Packet Rejected as UDP failed rule number, ",i," in UDP inbound rules"
							return False
					elif self.data["Inbound"]["UDP"][i][0] == 1:
						if UDPPort>self.data["Inbound"]["UDP"][i][1]:
							print "Packet Rejected as UDP failed rule number, ",i," in UDP inbound rules"
							return False
					else :
						if UDPPort>self.data["Inbound"]["UDP"][i][0] and UDPPort<self.data["Inbound"]["UDP"][i][1]:
							print "Packet Rejected as UDP failed rule number, ",i," in UDP inbound rules"
							return False
			return True
		if bool_outbound:
			if macAdd in self.data["Outbound"]["MAC"]:
				print "Packet Rejected as MacAdd failed"
				return False
			if bool_IPv4:
				if IPv4 in self.data["Outbound"]["IPv4"]:
					print "Packet Rejected as IPv4 failed"
					return False
			if bool_IPv6:
				if IPv6 in self.data["Outbound"]["IPv6"]:
					print "Packet Rejected as IPv6 failed"
					return False
			if bool_ICMP:
				for i in range(0,len(self.data["Outbound"]["ICMP"])):
					if self.data["Outbound"]["ICMP"][i][0] == -1:
						if ICMPPort<self.data["Outbound"]["ICMP"][i][1]:
							print "Packet Rejected as ICMP failed rule number, ",i," in ICMP Outbound rules"
							return False
					elif self.data["Outbound"]["ICMP"][i][0] == 0:
						if ICMPPort == self.data["Outbound"]["ICMP"][i][1]:
							print "Packet Rejected as ICMP failed rule number, ",i," in ICMP Outbound rules"
							return False
					elif self.data["Outbound"]["ICMP"][i][0] == 1:
						if ICMPPort>self.data["Outbound"]["ICMP"][i][1]:
							print "Packet Rejected as ICMP failed rule number, ",i," in ICMP Outbound rules"
							return False
					else :
						if ICMPPort>self.data["Outbound"]["ICMP"][i][0] and ICMPPort<self.data["Outbound"]["ICMP"][i][1]:
							print "Packet Rejected as ICMP failed rule number, ",i," in ICMP Outbound rules"
							return False
			if bool_TCP:
				for i in range(0,len(self.data["Outbound"]["TCP"])):
					if self.data["Outbound"]["TCP"][i][0] == -1:
						if TCPPort<self.data["Outbound"]["TCP"][i][1]:
							print "Packet Rejected as TCP failed rule number, ",i," in TCP Outbound rules"
							return False
					elif self.data["Outbound"]["TCP"][i][0] == 0:
						if TCPPort == self.data["Outbound"]["TCP"][i][1]:
							print "Packet Rejected as TCP failed rule number, ",i," in TCP Outbound rules"
							return False
					elif self.data["Outbound"]["TCP"][i][0] == 1:
						if TCPPort>self.data["Outbound"]["TCP"][i][1]:
							print "Packet Rejected as TCP failed rule number, ",i," in TCP Outbound rules"
							return False
					if TCPPort>self.data["Outbound"]["TCP"][i][0] and TCPPort<self.data["Outbound"]["TCP"][i][1]:
							print "Packet Rejected as TCP failed rule number, ",i," in TCP Outbound rules"
							return False
			if bool_UDP:
				for i in range(0,len(self.data["Outbound"]["UDP"])):
					if self.data["Outbound"]["UDP"][i][0] == -1:
						if UDPPort<self.data["Outbound"]["UDP"][i][1]:
							print "Packet Rejected as UDP failed rule number, ",i," in UDP Outbound rules"
							return False
					elif self.data["Outbound"]["UDP"][i][0] == 0:
						if UDPPort == self.data["Outbound"]["UDP"][i][1]:
							print "Packet Rejected as UDP failed rule number, ",i," in UDP Outbound rules"
							return False
					elif self.data["Outbound"]["UDP"][i][0] == 1:
						if UDPPort>self.data["Outbound"]["UDP"][i][1]:
							print "Packet Rejected as UDP failed rule number, ",i," in UDP Outbound rules"
							return False
					else :
						if UDPPort>self.data["Outbound"]["UDP"][i][0] and UDPPort<self.data["Outbound"]["UDP"][i][1]:
							print "Packet Rejected as UDP failed rule number, ",i," in UDP Outbound rules"
							return False

			return True
		pass

#-----this is where we rock-------#

print "Lets add some rules to the firewall just use close to start the firewall:"

myDict = {
	"Inbound":{
		"TCP":[
			#-1 ----> less than rule
			# 1 ----> Greater than rule
			# 0 ----> equal to rule
			(-1, 489 ) , 
			(-1, 490 ) , 
			(-1, 491 ) , 
			(-1, 492 ) , 
			(-1, 493 ) , 
			(-1, 494 ) , 
			(-1, 495 ) , 
			(-1, 496 ) , 
			(-1, 497 ) , 
			(-1, 498 ) , 
			(-1, 499 ) , 
			(-1, 500 ) , 
			(-1, 501 ) , 
			(-1, 502 ) , 
			(-1, 503 ) , 
			(-1, 504 ) , 
			(-1, 505 ) , 
			(-1, 506 ) , 
			(-1, 507 ) , 
			(-1, 508 ) , 
			(-1, 509 ) , 
			(-1, 510 ) , 
			(-1, 511 ) , 
			(-1, 512 ) , 
			(-1, 513 ) , 
			(-1, 514 ) , 
			(-1, 515 ) , 
			(-1, 516 ) , 
			(-1, 517 ) , 
			(-1, 518 ) , 
			(-1, 519 ) , 
			(-1, 520 ) , 
			(-1, 521 ) , 
			(-1, 522 ) , 
			(-1, 523 ) , 
			(-1, 524 ) , 
			(-1, 525 ) , 
			(-1, 526 ) , 
			(-1, 527 ) , 
			(-1, 528 ) , 
			(-1, 529 ) , 
			(-1, 530 ) , 
			(-1, 531 ) , 
			(-1, 532 ) , 
			(-1, 533 ) , 
			(-1, 534 ) , 
			(-1, 535 ) , 
			(-1, 536 ) , 
			(-1, 537 ) , 
			(-1, 538 ) , 
			(-1, 539 ) , 
			(-1, 540 ) , 
			(-1, 541 ) , 
			(-1, 542 ) , 
			(-1, 543 ) , 
			(-1, 544 ) , 
			(-1, 545 ) , 
			(-1, 546 ) , 
			(-1, 547 ) , 
			(-1, 548 ) , 
			(-1, 549 ) , 
			(-1, 550 ) , 
			(-1, 551 ) , 
			(-1, 552 ) , 
			(-1, 553 ) , 
			(-1, 554 ) , 
			(-1, 555 ) , 
			(-1, 556 ) , 
			(-1, 557 ) , 
			(-1, 558 ) , 
			(-1, 559 ) , 
			(-1, 560 ) , 
			(-1, 561 ) , 
			(-1, 562 ) , 
			(-1, 563 ) , 
			(-1, 564 ) , 
			(-1, 565 ) , 
			(-1, 566 ) , 
			(-1, 567 ) , 
			(-1, 568 ) , 
			(-1, 569 ) , 
			(-1, 570 ) , 
			(-1, 571 ) , 
			(-1, 572 ) , 
			(-1, 573 ) , 
			(-1, 574 ) , 
			(-1, 575 ) , 
			(-1, 576 ) , 
			(-1, 577 ) , 
			(-1, 578 ) , 
			(-1, 579 ) , 
			(-1, 580 ) , 
			(-1, 581 ) , 
			(-1, 582 ) , 
			(-1, 583 ) , 
			(-1, 584 ) , 
			(-1, 585 ) , 
			(-1, 586 ) , 
			(-1, 587 ) , 
			(-1, 588 ) , 
			(-1, 589 ) , 
			(-1, 590 ) , 
			(-1, 591 ) , 
			(-1, 592 ) , 
			(-1, 593 ) , 
			(-1, 594 ) , 
			(-1, 595 ) , 
			(-1, 596 ) , 
			(-1, 597 ) , 
			(-1, 598 ) , 
			(-1, 599 ) , 
			(-1, 600 ) , 
			(-1, 601 ) , 
			(-1, 602 ) , 
			(-1, 603 ) , 
			(-1, 604 ) , 
			(-1, 605 ) , 
			(-1, 606 ) , 
			(-1, 607 ) , 
			(-1, 608 ) , 
			(-1, 609 ) , 
			(-1, 610 ) , 
			(-1, 611 ) , 
			(-1, 612 ) , 
			(-1, 613 ) , 
			(-1, 614 ) , 
			(-1, 615 ) , 
			(-1, 616 ) , 
			(-1, 617 ) , 
			(-1, 618 ) , 
			(-1, 619 ) , 
			(-1, 620 ) , 
			(-1, 621 ) , 
			(-1, 622 ) , 
			(-1, 623 ) , 
			(-1, 624 ) , 
			(-1, 625 ) , 
			(-1, 626 ) , 
			(-1, 627 ) , 
			(-1, 628 ) , 
			(-1, 629 ) , 
			(-1, 630 ) , 
			(-1, 631 ) , 
			(-1, 632 ) , 
			(-1, 633 ) , 
			(-1, 634 ) , 
			(-1, 635 ) , 
			(-1, 636 ) , 
			(-1, 637 ) , 
			(-1, 638 ) , 
			(-1, 639 ) , 
			(-1, 640 ) , 
			(-1, 641 ) , 
			(-1, 642 ) , 
			(-1, 643 ) , 
			(-1, 644 ) , 
			(-1, 645 ) , 
			(-1, 646 ) , 
			(-1, 647 ) , 
			(-1, 648 ) , 
			(-1, 649 ) , 
			(-1, 650 ) , 
			(-1, 651 ) , 
			(-1, 652 ) , 
			(-1, 653 ) , 
			(-1, 654 ) , 
			(-1, 655 ) , 
			(-1, 656 ) , 
			(-1, 657 ) , 
			(-1, 658 ) , 
			(-1, 659 ) , 
			(-1, 660 ) , 
			(-1, 661 ) , 
			(-1, 662 ) , 
			(-1, 663 ) , 
			(-1, 664 ) , 
			(-1, 665 ) , 
			(-1, 666 ) , 
			(-1, 667 ) , 
			(-1, 668 ) , 
			(-1, 669 ) , 
			(-1, 670 ) , 
			(-1, 671 ) , 
			(-1, 672 ) , 
			(-1, 673 ) , 
			(-1, 674 ) , 
			(-1, 675 ) , 
			(-1, 676 ) , 
			(-1, 677 ) , 
			(-1, 678 ) , 
			(-1, 679 ) , 
			(-1, 680 ) , 
			(-1, 681 ) , 
			(-1, 682 ) , 
			(-1, 683 ) , 
			(-1, 684 ) , 
			(-1, 685 ) , 
			(-1, 686 ) , 
			(-1, 687 ) , 
			(-1, 688 ) , 
			(-1, 689 ) , 
			(-1, 690 ) , 
			(-1, 691 ) , 
			(-1, 692 ) , 
			(-1, 693 ) , 
			(-1, 694 ) , 
			(-1, 695 ) , 
			(-1, 696 ) , 
			(-1, 697 ) , 
			(-1, 698 ) , 
			(-1, 699 ) , 
			(-1, 700 ) , 
			(-1, 701 ) , 
			(-1, 702 ) , 
			(-1, 703 ) , 
			(-1, 704 ) , 
			(-1, 705 ) , 
			(-1, 706 ) , 
			(-1, 707 ) , 
			(-1, 708 ) , 
			(-1, 709 ) , 
			(-1, 710 ) , 
			(-1, 711 ) , 
			(-1, 712 ) , 
			(-1, 713 ) , 
			(-1, 714 ) , 
			(-1, 715 ) , 
			(-1, 716 ) , 
			(-1, 717 ) , 
			(-1, 718 ) , 
			(-1, 719 ) , 
			(-1, 720 ) , 
			(-1, 721 ) , 
			(-1, 722 ) , 
			(-1, 723 ) , 
			(-1, 724 ) , 
			(-1, 725 ) , 
			(-1, 726 ) , 
			(-1, 727 ) , 
			(-1, 728 ) , 
			(-1, 729 ) , 
			(-1, 730 ) , 
			(-1, 731 ) , 
			(-1, 732 ) , 
			(-1, 733 ) , 
			(-1, 734 ) , 
			(-1, 735 ) , 
			(-1, 736 ) , 
			(-1, 737 ) , 
			(-1, 738 ) , 
			(-1, 739 ) , 
			(-1, 740 ) , 
			(-1, 741 ) , 
			(-1, 742 ) , 
			(-1, 743 ) , 
			(-1, 744 ) , 
			(-1, 745 ) , 
			(-1, 746 ) , 
			(-1, 747 ) , 
			(-1, 748 ) , 
			(-1, 749 ) , 
			(-1, 750 ) , 
			(-1, 751 ) , 
			(-1, 752 ) , 
			(-1, 753 ) , 
			(-1, 754 ) , 
			(-1, 755 ) , 
			(-1, 756 ) , 
			(-1, 757 ) , 
			(-1, 758 ) , 
			(-1, 759 ) , 
			(-1, 760 ) , 
			(-1, 761 ) , 
			(-1, 762 ) , 
			(-1, 763 ) , 
			(-1, 764 ) , 
			(-1, 765 ) , 
			(-1, 766 ) , 
			(-1, 767 ) , 
			(-1, 768 ) , 
			(-1, 769 ) , 
			(-1, 770 ) , 
			(-1, 771 ) , 
			(-1, 772 ) , 
			(-1, 773 ) , 
			(-1, 774 ) , 
			(-1, 775 ) , 
			(-1, 776 ) , 
			(-1, 777 ) , 
			(-1, 778 ) , 
			(-1, 779 ) , 
			(-1, 780 ) , 
			(-1, 781 ) , 
			(-1, 782 ) , 
			(-1, 783 ) , 
			(-1, 784 ) , 
			(-1, 785 ) , 
			(-1, 786 ) , 
			(-1, 787 ) , 
			(-1, 788 ) , 
			(-1, 789 ) , 
			(-1, 790 ) , 
			(-1, 791 ) , 
			(-1, 792 ) , 
			(-1, 793 ) , 
			(-1, 794 ) , 
			(-1, 795 ) , 
			(-1, 796 ) , 
			(-1, 797 ) , 
			(-1, 798 ) , 
			(-1, 799 ) , 
			(-1, 800 ) , 
			(-1, 801 ) , 
			(-1, 802 ) , 
			(-1, 803 ) , 
			(-1, 804 ) , 
			(-1, 805 ) , 
			(-1, 806 ) , 
			(-1, 807 ) , 
			(-1, 808 ) , 
			(-1, 809 ) , 
			(-1, 810 ) , 
			(-1, 811 ) , 
			(-1, 812 ) , 
			(-1, 813 ) , 
			(-1, 814 ) , 
			(-1, 815 ) , 
			(-1, 816 ) , 
			(-1, 817 ) , 
			(-1, 818 ) , 
			(-1, 819 ) , 
			(-1, 820 ) , 
			(-1, 821 ) , 
			(-1, 822 ) , 
			(-1, 823 ) , 
			(-1, 824 ) , 
			(-1, 825 ) , 
			(-1, 826 ) , 
			(-1, 827 ) , 
			(-1, 828 ) , 
			(-1, 829 ) , 
			(-1, 830 ) , 
			(-1, 831 ) , 
			(-1, 832 ) , 
			(-1, 833 ) , 
			(-1, 834 ) , 
			(-1, 835 ) , 
			(-1, 836 ) , 
			(-1, 837 ) , 
			(-1, 838 ) , 
			(-1, 839 ) , 
			(-1, 840 ) , 
			(-1, 841 ) , 
			(-1, 842 ) , 
			(-1, 843 ) , 
			(-1, 844 ) , 
			(-1, 845 ) , 
			(-1, 846 ) , 
			(-1, 847 ) , 
			(-1, 848 ) , 
			(-1, 849 ) , 
			(-1, 850 ) , 
			(-1, 851 ) , 
			(-1, 852 ) , 
			(-1, 853 ) , 
			(-1, 854 ) , 
			(-1, 855 ) , 
			(-1, 856 ) , 
			(-1, 857 ) , 
			(-1, 858 ) , 
			(-1, 859 ) , 
			(-1, 860 ) , 
			(-1, 861 ) , 
			(-1, 862 ) , 
			(-1, 863 ) , 
			(-1, 864 ) , 
			(-1, 865 ) , 
			(-1, 866 ) , 
			(-1, 867 ) , 
			(-1, 868 ) , 
			(-1, 869 ) , 
			(-1, 870 ) , 
			(-1, 871 ) , 
			(-1, 872 ) , 
			(-1, 873 ) , 
			(-1, 874 ) , 
			(-1, 875 ) , 
			(-1, 876 ) , 
			(-1, 877 ) , 
			(-1, 878 ) , 
			(-1, 879 ) , 
			(-1, 880 ) , 
			(-1, 881 ) , 
			(-1, 882 ) , 
			(-1, 883 ) , 
			(-1, 884 ) , 
			(-1, 885 ) , 
			(-1, 886 ) , 
			(-1, 887 ) , 
			(-1, 888 ) , 
			(-1, 889 ) , 
			(-1, 890 ) , 
			(-1, 891 ) , 
			(-1, 892 ) , 
			(-1, 893 ) , 
			(-1, 894 ) , 
			(-1, 895 ) , 
			(-1, 896 ) , 
			(-1, 897 ) , 
			(-1, 898 ) , 
			(-1, 899 ) , 
			(-1, 900 ) , 
			(-1, 901 ) , 
			(-1, 902 ) , 
			(-1, 903 ) , 
			(-1, 904 ) , 
			(-1, 905 ) , 
			(-1, 906 ) , 
			(-1, 907 ) , 
			(-1, 908 ) , 
			(-1, 909 ) , 
			(-1, 910 ) , 
			(-1, 911 ) , 
			(-1, 912 ) , 
			(-1, 913 ) , 
			(-1, 914 ) , 
			(-1, 915 ) , 
			(-1, 916 ) , 
			(-1, 917 ) , 
			(-1, 918 ) , 
			(-1, 919 ) , 
			(-1, 920 ) , 
			(-1, 921 ) , 
			(-1, 922 ) , 
			(-1, 923 ) , 
			(-1, 924 ) , 
			(-1, 925 ) , 
			(-1, 926 ) , 
			(-1, 927 ) , 
			(-1, 928 ) , 
			(-1, 929 ) , 
			(-1, 930 ) , 
			(-1, 931 ) , 
			(-1, 932 ) , 
			(-1, 933 ) , 
			(-1, 934 ) , 
			(-1, 935 ) , 
			(-1, 936 ) , 
			(-1, 937 ) , 
			(-1, 938 ) , 
			(-1, 939 ) , 
			(-1, 940 ) , 
			(-1, 941 ) , 
			(-1, 942 ) , 
			(-1, 943 ) , 
			(-1, 944 ) , 
			(-1, 945 ) , 
			(-1, 946 ) , 
			(-1, 947 ) , 
			(-1, 948 ) , 
			(-1, 949 ) , 
			(-1, 950 ) , 
			(-1, 951 ) , 
			(-1, 952 ) , 
			(-1, 953 ) , 
			(-1, 954 ) , 
			(-1, 955 ) , 
			(-1, 956 ) , 
			(-1, 957 ) , 
			(-1, 958 ) , 
			(-1, 959 ) , 
			(-1, 960 ) , 
			(-1, 961 ) , 
			(-1, 962 ) , 
			(-1, 963 ) , 
			(-1, 964 ) , 
			(-1, 965 ) , 
			(-1, 966 ) , 
			(-1, 967 ) , 
			(-1, 968 ) , 
			(-1, 969 ) , 
			(-1, 970 ) , 
			(-1, 971 ) , 
			(-1, 972 ) , 
			(-1, 973 ) , 
			(-1, 974 ) , 
			(-1, 975 ) , 
			(-1, 976 ) , 
			(-1, 977 ) , 
			(-1, 978 ) , 
			(-1, 979 ) , 
			(-1, 980 ) , 
			(-1, 981 ) , 
			(-1, 982 ) , 
			(-1, 983 ) , 
			(-1, 984 ) , 
			(-1, 985 ) , 
			(-1, 986 ) , 
			(-1, 987 ) , 
			(-1, 988 ) , 
			(-1, 989 ) , 
			(-1, 990 ) , 
			(-1, 991 ) , 
			(-1, 992 ) , 
			(-1, 993 ) , 
			(-1, 994 ) , 
			(-1, 995 ) , 
			(-1, 996 ) , 
			(-1, 997 ) , 
			(-1, 998 ) , 
			(-1, 999 )

		],
		"UDP":[
			#-1 ----> less than rule
			# 1 ----> Greater than rule
			# 0 ----> equal to rule
			(-1, 489 ) , 
			(-1, 490 ) , 
			(-1, 491 ) , 
			(-1, 492 ) , 
			(-1, 493 ) , 
			(-1, 494 ) , 
			(-1, 495 ) , 
			(-1, 496 ) , 
			(-1, 497 ) , 
			(-1, 498 ) , 
			(-1, 499 ) , 
			(-1, 500 ) , 
			(-1, 501 ) , 
			(-1, 502 ) , 
			(-1, 503 ) , 
			(-1, 504 ) , 
			(-1, 505 ) , 
			(-1, 506 ) , 
			(-1, 507 ) , 
			(-1, 508 ) , 
			(-1, 509 ) , 
			(-1, 510 ) , 
			(-1, 511 ) , 
			(-1, 512 ) , 
			(-1, 513 ) , 
			(-1, 514 ) , 
			(-1, 515 ) , 
			(-1, 516 ) , 
			(-1, 517 ) , 
			(-1, 518 ) , 
			(-1, 519 ) , 
			(-1, 520 ) , 
			(-1, 521 ) , 
			(-1, 522 ) , 
			(-1, 523 ) , 
			(-1, 524 ) , 
			(-1, 525 ) , 
			(-1, 526 ) , 
			(-1, 527 ) , 
			(-1, 528 ) , 
			(-1, 529 ) , 
			(-1, 530 ) , 
			(-1, 531 ) , 
			(-1, 532 ) , 
			(-1, 533 ) , 
			(-1, 534 ) , 
			(-1, 535 ) , 
			(-1, 536 ) , 
			(-1, 537 ) , 
			(-1, 538 ) , 
			(-1, 539 ) , 
			(-1, 540 ) , 
			(-1, 541 ) , 
			(-1, 542 ) , 
			(-1, 543 ) , 
			(-1, 544 ) , 
			(-1, 545 ) , 
			(-1, 546 ) , 
			(-1, 547 ) , 
			(-1, 548 ) , 
			(-1, 549 ) , 
			(-1, 550 ) , 
			(-1, 551 ) , 
			(-1, 552 ) , 
			(-1, 553 ) , 
			(-1, 554 ) , 
			(-1, 555 ) , 
			(-1, 556 ) , 
			(-1, 557 ) , 
			(-1, 558 ) , 
			(-1, 559 ) , 
			(-1, 560 ) , 
			(-1, 561 ) , 
			(-1, 562 ) , 
			(-1, 563 ) , 
			(-1, 564 ) , 
			(-1, 565 ) , 
			(-1, 566 ) , 
			(-1, 567 ) , 
			(-1, 568 ) , 
			(-1, 569 ) , 
			(-1, 570 ) , 
			(-1, 571 ) , 
			(-1, 572 ) , 
			(-1, 573 ) , 
			(-1, 574 ) , 
			(-1, 575 ) , 
			(-1, 576 ) , 
			(-1, 577 ) , 
			(-1, 578 ) , 
			(-1, 579 ) , 
			(-1, 580 ) , 
			(-1, 581 ) , 
			(-1, 582 ) , 
			(-1, 583 ) , 
			(-1, 584 ) , 
			(-1, 585 ) , 
			(-1, 586 ) , 
			(-1, 587 ) , 
			(-1, 588 ) , 
			(-1, 589 ) , 
			(-1, 590 ) , 
			(-1, 591 ) , 
			(-1, 592 ) , 
			(-1, 593 ) , 
			(-1, 594 ) , 
			(-1, 595 ) , 
			(-1, 596 ) , 
			(-1, 597 ) , 
			(-1, 598 ) , 
			(-1, 599 ) , 
			(-1, 600 ) , 
			(-1, 601 ) , 
			(-1, 602 ) , 
			(-1, 603 ) , 
			(-1, 604 ) , 
			(-1, 605 ) , 
			(-1, 606 ) , 
			(-1, 607 ) , 
			(-1, 608 ) , 
			(-1, 609 ) , 
			(-1, 610 ) , 
			(-1, 611 ) , 
			(-1, 612 ) , 
			(-1, 613 ) , 
			(-1, 614 ) , 
			(-1, 615 ) , 
			(-1, 616 ) , 
			(-1, 617 ) , 
			(-1, 618 ) , 
			(-1, 619 ) , 
			(-1, 620 ) , 
			(-1, 621 ) , 
			(-1, 622 ) , 
			(-1, 623 ) , 
			(-1, 624 ) , 
			(-1, 625 ) , 
			(-1, 626 ) , 
			(-1, 627 ) , 
			(-1, 628 ) , 
			(-1, 629 ) , 
			(-1, 630 ) , 
			(-1, 631 ) , 
			(-1, 632 ) , 
			(-1, 633 ) , 
			(-1, 634 ) , 
			(-1, 635 ) , 
			(-1, 636 ) , 
			(-1, 637 ) , 
			(-1, 638 ) , 
			(-1, 639 ) , 
			(-1, 640 ) , 
			(-1, 641 ) , 
			(-1, 642 ) , 
			(-1, 643 ) , 
			(-1, 644 ) , 
			(-1, 645 ) , 
			(-1, 646 ) , 
			(-1, 647 ) , 
			(-1, 648 ) , 
			(-1, 649 ) , 
			(-1, 650 ) , 
			(-1, 651 ) , 
			(-1, 652 ) , 
			(-1, 653 ) , 
			(-1, 654 ) , 
			(-1, 655 ) , 
			(-1, 656 ) , 
			(-1, 657 ) , 
			(-1, 658 ) , 
			(-1, 659 ) , 
			(-1, 660 ) , 
			(-1, 661 ) , 
			(-1, 662 ) , 
			(-1, 663 ) , 
			(-1, 664 ) , 
			(-1, 665 ) , 
			(-1, 666 ) , 
			(-1, 667 ) , 
			(-1, 668 ) , 
			(-1, 669 ) , 
			(-1, 670 ) , 
			(-1, 671 ) , 
			(-1, 672 ) , 
			(-1, 673 ) , 
			(-1, 674 ) , 
			(-1, 675 ) , 
			(-1, 676 ) , 
			(-1, 677 ) , 
			(-1, 678 ) , 
			(-1, 679 ) , 
			(-1, 680 ) , 
			(-1, 681 ) , 
			(-1, 682 ) , 
			(-1, 683 ) , 
			(-1, 684 ) , 
			(-1, 685 ) , 
			(-1, 686 ) , 
			(-1, 687 ) , 
			(-1, 688 ) , 
			(-1, 689 ) , 
			(-1, 690 ) , 
			(-1, 691 ) , 
			(-1, 692 ) , 
			(-1, 693 ) , 
			(-1, 694 ) , 
			(-1, 695 ) , 
			(-1, 696 ) , 
			(-1, 697 ) , 
			(-1, 698 ) , 
			(-1, 699 ) , 
			(-1, 700 ) , 
			(-1, 701 ) , 
			(-1, 702 ) , 
			(-1, 703 ) , 
			(-1, 704 ) , 
			(-1, 705 ) , 
			(-1, 706 ) , 
			(-1, 707 ) , 
			(-1, 708 ) , 
			(-1, 709 ) , 
			(-1, 710 ) , 
			(-1, 711 ) , 
			(-1, 712 ) , 
			(-1, 713 ) , 
			(-1, 714 ) , 
			(-1, 715 ) , 
			(-1, 716 ) , 
			(-1, 717 ) , 
			(-1, 718 ) , 
			(-1, 719 ) , 
			(-1, 720 ) , 
			(-1, 721 ) , 
			(-1, 722 ) , 
			(-1, 723 ) , 
			(-1, 724 ) , 
			(-1, 725 ) , 
			(-1, 726 ) , 
			(-1, 727 ) , 
			(-1, 728 ) , 
			(-1, 729 ) , 
			(-1, 730 ) , 
			(-1, 731 ) , 
			(-1, 732 ) , 
			(-1, 733 ) , 
			(-1, 734 ) , 
			(-1, 735 ) , 
			(-1, 736 ) , 
			(-1, 737 ) , 
			(-1, 738 ) , 
			(-1, 739 ) , 
			(-1, 740 ) , 
			(-1, 741 ) , 
			(-1, 742 ) , 
			(-1, 743 ) , 
			(-1, 744 ) , 
			(-1, 745 ) , 
			(-1, 746 ) , 
			(-1, 747 ) , 
			(-1, 748 ) , 
			(-1, 749 ) , 
			(-1, 750 ) , 
			(-1, 751 ) , 
			(-1, 752 ) , 
			(-1, 753 ) , 
			(-1, 754 ) , 
			(-1, 755 ) , 
			(-1, 756 ) , 
			(-1, 757 ) , 
			(-1, 758 ) , 
			(-1, 759 ) , 
			(-1, 760 ) , 
			(-1, 761 ) , 
			(-1, 762 ) , 
			(-1, 763 ) , 
			(-1, 764 ) , 
			(-1, 765 ) , 
			(-1, 766 ) , 
			(-1, 767 ) , 
			(-1, 768 ) , 
			(-1, 769 ) , 
			(-1, 770 ) , 
			(-1, 771 ) , 
			(-1, 772 ) , 
			(-1, 773 ) , 
			(-1, 774 ) , 
			(-1, 775 ) , 
			(-1, 776 ) , 
			(-1, 777 ) , 
			(-1, 778 ) , 
			(-1, 779 ) , 
			(-1, 780 ) , 
			(-1, 781 ) , 
			(-1, 782 ) , 
			(-1, 783 ) , 
			(-1, 784 ) , 
			(-1, 785 ) , 
			(-1, 786 ) , 
			(-1, 787 ) , 
			(-1, 788 ) , 
			(-1, 789 ) , 
			(-1, 790 ) , 
			(-1, 791 ) , 
			(-1, 792 ) , 
			(-1, 793 ) , 
			(-1, 794 ) , 
			(-1, 795 ) , 
			(-1, 796 ) , 
			(-1, 797 ) , 
			(-1, 798 ) , 
			(-1, 799 ) , 
			(-1, 800 ) , 
			(-1, 801 ) , 
			(-1, 802 ) , 
			(-1, 803 ) , 
			(-1, 804 ) , 
			(-1, 805 ) , 
			(-1, 806 ) , 
			(-1, 807 ) , 
			(-1, 808 ) , 
			(-1, 809 ) , 
			(-1, 810 ) , 
			(-1, 811 ) , 
			(-1, 812 ) , 
			(-1, 813 ) , 
			(-1, 814 ) , 
			(-1, 815 ) , 
			(-1, 816 ) , 
			(-1, 817 ) , 
			(-1, 818 ) , 
			(-1, 819 ) , 
			(-1, 820 ) , 
			(-1, 821 ) , 
			(-1, 822 ) , 
			(-1, 823 ) , 
			(-1, 824 ) , 
			(-1, 825 ) , 
			(-1, 826 ) , 
			(-1, 827 ) , 
			(-1, 828 ) , 
			(-1, 829 ) , 
			(-1, 830 ) , 
			(-1, 831 ) , 
			(-1, 832 ) , 
			(-1, 833 ) , 
			(-1, 834 ) , 
			(-1, 835 ) , 
			(-1, 836 ) , 
			(-1, 837 ) , 
			(-1, 838 ) , 
			(-1, 839 ) , 
			(-1, 840 ) , 
			(-1, 841 ) , 
			(-1, 842 ) , 
			(-1, 843 ) , 
			(-1, 844 ) , 
			(-1, 845 ) , 
			(-1, 846 ) , 
			(-1, 847 ) , 
			(-1, 848 ) , 
			(-1, 849 ) , 
			(-1, 850 ) , 
			(-1, 851 ) , 
			(-1, 852 ) , 
			(-1, 853 ) , 
			(-1, 854 ) , 
			(-1, 855 ) , 
			(-1, 856 ) , 
			(-1, 857 ) , 
			(-1, 858 ) , 
			(-1, 859 ) , 
			(-1, 860 ) , 
			(-1, 861 ) , 
			(-1, 862 ) , 
			(-1, 863 ) , 
			(-1, 864 ) , 
			(-1, 865 ) , 
			(-1, 866 ) , 
			(-1, 867 ) , 
			(-1, 868 ) , 
			(-1, 869 ) , 
			(-1, 870 ) , 
			(-1, 871 ) , 
			(-1, 872 ) , 
			(-1, 873 ) , 
			(-1, 874 ) , 
			(-1, 875 ) , 
			(-1, 876 ) , 
			(-1, 877 ) , 
			(-1, 878 ) , 
			(-1, 879 ) , 
			(-1, 880 ) , 
			(-1, 881 ) , 
			(-1, 882 ) , 
			(-1, 883 ) , 
			(-1, 884 ) , 
			(-1, 885 ) , 
			(-1, 886 ) , 
			(-1, 887 ) , 
			(-1, 888 ) , 
			(-1, 889 ) , 
			(-1, 890 ) , 
			(-1, 891 ) , 
			(-1, 892 ) , 
			(-1, 893 ) , 
			(-1, 894 ) , 
			(-1, 895 ) , 
			(-1, 896 ) , 
			(-1, 897 ) , 
			(-1, 898 ) , 
			(-1, 899 ) , 
			(-1, 900 ) , 
			(-1, 901 ) , 
			(-1, 902 ) , 
			(-1, 903 ) , 
			(-1, 904 ) , 
			(-1, 905 ) , 
			(-1, 906 ) , 
			(-1, 907 ) , 
			(-1, 908 ) , 
			(-1, 909 ) , 
			(-1, 910 ) , 
			(-1, 911 ) , 
			(-1, 912 ) , 
			(-1, 913 ) , 
			(-1, 914 ) , 
			(-1, 915 ) , 
			(-1, 916 ) , 
			(-1, 917 ) , 
			(-1, 918 ) , 
			(-1, 919 ) , 
			(-1, 920 ) , 
			(-1, 921 ) , 
			(-1, 922 ) , 
			(-1, 923 ) , 
			(-1, 924 ) , 
			(-1, 925 ) , 
			(-1, 926 ) , 
			(-1, 927 ) , 
			(-1, 928 ) , 
			(-1, 929 ) , 
			(-1, 930 ) , 
			(-1, 931 ) , 
			(-1, 932 ) , 
			(-1, 933 ) , 
			(-1, 934 ) , 
			(-1, 935 ) , 
			(-1, 936 ) , 
			(-1, 937 ) , 
			(-1, 938 ) , 
			(-1, 939 ) , 
			(-1, 940 ) , 
			(-1, 941 ) , 
			(-1, 942 ) , 
			(-1, 943 ) , 
			(-1, 944 ) , 
			(-1, 945 ) , 
			(-1, 946 ) , 
			(-1, 947 ) , 
			(-1, 948 ) , 
			(-1, 949 ) , 
			(-1, 950 ) , 
			(-1, 951 ) , 
			(-1, 952 ) , 
			(-1, 953 ) , 
			(-1, 954 ) , 
			(-1, 955 ) , 
			(-1, 956 ) , 
			(-1, 957 ) , 
			(-1, 958 ) , 
			(-1, 959 ) , 
			(-1, 960 ) , 
			(-1, 961 ) , 
			(-1, 962 ) , 
			(-1, 963 ) , 
			(-1, 964 ) , 
			(-1, 965 ) , 
			(-1, 966 ) , 
			(-1, 967 ) , 
			(-1, 968 ) , 
			(-1, 969 ) , 
			(-1, 970 ) , 
			(-1, 971 ) , 
			(-1, 972 ) , 
			(-1, 973 ) , 
			(-1, 974 ) , 
			(-1, 975 ) , 
			(-1, 976 ) , 
			(-1, 977 ) , 
			(-1, 978 ) , 
			(-1, 979 ) , 
			(-1, 980 ) , 
			(-1, 981 ) , 
			(-1, 982 ) , 
			(-1, 983 ) , 
			(-1, 984 ) , 
			(-1, 985 ) , 
			(-1, 986 ) , 
			(-1, 987 ) , 
			(-1, 988 ) , 
			(-1, 989 ) , 
			(-1, 990 ) , 
			(-1, 991 ) , 
			(-1, 992 ) , 
			(-1, 993 ) , 
			(-1, 994 ) , 
			(-1, 995 ) , 
			(-1, 996 ) , 
			(-1, 997 ) , 
			(-1, 998 ) , 
			(-1, 999 )
		],
		"MAC":[
			"6c:c2:17:6s:04:c5"
		],
		"IPv4":[
			"192.168.35.5"
		],
		"IPv6":[
			"2001:db8:85a3:0:0:8a2e:370:7334"
		],
		"ICMP":[
			#-1 ----> less than rule
			# 1 ----> Greater than rule
			# 0 ----> equal to rule
			(1,30000)
		]
	},
	"Outbound":{
		"TCP":[
			#-1 ----> less than rule
			# 1 ----> Greater than rule
			# 0 ----> equal to rule
			(-1,100)
		],
		"UDP":[
			#-1 ----> less than rule
			# 1 ----> Greater than rule
			# 0 ----> equal to rule
			(-1,200)
		],
		"MAC":[
			"6c:c2:17:6s:04:c5"
		],
		"IPv4":[
			"192.168.35.5"
		],
		"IPv6":[
			"2001:db8:85a3:0:0:8a2e:370:7334"
		],
		"ICMP":[
			#-1 ----> less than rule
			# 1 ----> Greater than rule
			# 0 ----> equal to rule
			(1,30000)
		]
	}
}

mySet = Ruleset(myDict);

while 1:
	print "Operations:"
	print "1.Add"
	print "2.delete"
	print "3.update"
	print "4.Show Stats"
	print "5.Close"
	x = input("input the id of operation:")
	if x == 1 or x == 2 or x == 3:
		rule_type = input("input rule type 1.inbound or 2.outbound (just give the id of rule):")
		in_type = input("input type(1.MAC,2.IPv4,3.IPv6,4.ICMP,5.TCP,6.UDP):")
		if x == 1:
			mySet.add(rule_type,in_type)
		if x == 2:
			mySet.delete(rule_type,in_type)
		if x == 3:
			mySet.update(rule_type,in_type)
	elif x == 4:
		mySet.stats()
	elif x== 5:
		break
	else:
		print "give correct id of operation:"






def eth_addr (a) :
  b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
  return b
 
#create a AF_PACKET type raw socket (thats basically packet level)
#define ETH_P_ALL    0x0003         
try:
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0800))
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()
 
# receive a packet
dictas={}
dictlis=[]
while True:
    packet = s.recvfrom(65565)
     
    #packet string from tuple
    packet = packet[0]
     
    #parse ethernet header
    eth_length = 14
     
    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH' , eth_header)
    eth_protocol = socket.ntohs(eth[2])
    if str(eth_addr(packet[6:12])) != "b8:2a:72:cb:71:04":
	continue
    print 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol)
    #Parse IP packets, IP Protocol number = 8
    if eth_protocol == 8 :
        #Parse IP header
        #take first 20 characters for the ip header
	        
	ip_header = packet[eth_length:20+eth_length]
        
        #now unpack them :)
        iph = unpack('!HHIIHHHH' , ip_header)			#unpacking the ip header
 	print iph
 	iph_length = iph[2]
	version=iph[0]
 	ttl = iph[3]
        protocol = iph[1]
 	s_addr = (iph[4]);
        d_addr = str(iph[4])+'.'+str(iph[5])+'.'+str(iph[6])+'.'+str(iph[7]);
        print 'Version : ' + str(version) + ' IP Header Length : ' + str(iph_length) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)
 	
	src_mac = str(eth_addr(packet[6:12]))
	
	
        #TCP protocol
        if protocol == 6 :
            t = iph_length + eth_length
            tcp_header = packet[t:t+12]
 
            #now unpack them :)
            tcph = unpack('!HHLL' , tcp_header)
             
            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            #doff_reserved = tcph[4]
            #tcph_length = doff_reserved >> 4
	    tcph_length = 12
             
            print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)

            x=(src_mac,True,d_addr,False,"",False,"",True,dest_port,False,0,True,False)
            
	    if mySet.verify(src_mac,True,d_addr,False,"",False,0,True,dest_port,False,0,True,False):
		print "ok acc to rules"
	    else:
		continue
            h_size = eth_length + iph_length + tcph_length		#header size
            data_size = len(packet) - h_size
             
            #get data from the packet
            data = packet[h_size:]
            soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	    print d_addr
	    print dest_port
	    soc.connect((d_addr,dest_port))
	    soc.sendall(data)
	    soc.close()
            print 'Data : ' + data
 
        #ICMP Packets
        elif protocol == 1 :
            u = iph_length + eth_length
            icmph_length = 4
            icmp_header = packet[u:u+4]
 
            #now unpack them :)
            icmph = unpack('!BBH' , icmp_header)
             
            icmp_type = icmph[0]
            code = icmph[1]
            checksum = icmph[2]
             
            print 'Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum)
             
            h_size = eth_length + iph_length + icmph_length
            data_size = len(packet) - h_size
             
            #get data from the packet
            data = packet[h_size:]
            soc = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
	    soc.sendto(data,(d_addr,8888)) 
             
            print 'Data : ' + data
 
        #UDP packets
        elif protocol == 17 :
            u = iph_length + eth_length
            udph_length = 8
            udp_header = packet[u:u+8]
 
            #now unpack them :)
            udph = unpack('!HHHH' , udp_header)
             
            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            checksum = udph[3]
             
            print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum)
            x = (src_mac,True,d_addr,False,"",False,0,True,dest_port,False,0,True,False)
	    if mySet.verify(src_mac,True,d_addr,False,"",False,0,True,dest_port,False,0,True,False):
		print "ok acc to rules"
	    else:
		continue
            h_size = eth_length + iph_length + udph_length
            data_size = len(packet) - h_size
             
            #get data from the packet
            data = packet[h_size:]
            soc = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	    soc.sendto(data,(d_addr,dest_port))
	    soc.close()
            print 'Data : ' + data
 
        #some other IP packet like IGMP
        else :
            print 'Protocol other than TCP/UDP/ICMP'
             
        print
