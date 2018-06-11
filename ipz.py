#!/usr/bin/env python
#-*-   encoding: utf-8 -*-
#this class change ip to network id etc.
"""Usage:
  ipy <ip> <netmask> [range]
  ipy (-h | --help)
Options:
  -h --help    Show this screen.
  ip           Give a ip
  netmask      Give a netmask
  range        show use some ip in network
"""


from docopt import docopt
import re


mask_mod = {
    '1': '128.0.0.0', '9': '255.128.0.0',  '17': '255.255.128.0', '25': '255.255.255.128',
    '2': '192.0.0.0', '10': '255.192.0.0', '18': '255.255.192.0', '26': '255.255.255.192',
    '3': '224.0.0.0', '11': '225.224.0.0', '19': '255.255.224.0', '27': '255.255.255.224',
    '4': '240.0.0.0', '12': '255.240.0.0', '20': '255.255.240.0', '28': '255.255.255.240',
    '5': '248.0.0.0', '13': '255.248.0.0', '21': '255.255.248.0', '29': '255.255.255.248',
    '6': '225.0.0.0', '14': '255.252.0.0', '22': '255.255.252.0', '30': '255.255.255.252',
    '7': '254.0.0.0', '15': '255.254.0.0', '23': '255.255.254.0', '31': '255.255.255.254',
    '8': '255.0.0.0', '16': '255.255.0.0', '24': '255.255.255.0', '32': '255.255.255.255',
}


class Requirements(object):
    def __init__(self, ip, mask):
        super(Requirements, self).__init__()
        self.ip = str(ip)
        self.mask = str(mask)

    #ip输入格式检查
    def formatCheck(self):
        ip, mask = self.ip, self.mask
        formatCheck_dict = {'errcode': 1, 'errmsg': []}
        #点分十进制ip地址检查
        if re.match("^(([01]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])(\.([01]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])){3}|([0-9a-fA-F]{1,4}:)+:?([0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4})$", ip) == None:
            #二进制IP地址检查
            if re.match("[1|0]{32}", ip) == None:
                formatCheck_dict['errmsg'].append('ERROR_IP_FORMAT')
                formatCheck_dict['errcode'] = 2
        #子网掩码检查合法性
        if mask not in mask_mod:
            if mask not in mask_mod.values():
                formatCheck_dict['errmsg'].append('ERROR_NETMASK_FORMAT')
                formatCheck_dict['errcode'] = 3
        if formatCheck_dict['errmsg'] == []:
            formatCheck_dict['errcode'] = 0
        return formatCheck_dict

    #输入点分十进制或者二进制都能给出十进制和二进制的字典集合
    def formatChange(self, var, type='dotted_decimal'):
        var = str(var)
        var_formats_dict = {'bin': '', 'dotted_decimal': ''}
        if type == "dotted_decimal":
            var_bin = "".join([ bin(int(i)).split('b')[1].zfill(8) for i in var.split('.')])
            var_formats_dict['bin'] = var_bin
            var_formats_dict['dotted_decimal'] = var
        elif type == "bin":
            var = var.zfill(32)
            var_dotted_decimal = ".".join([ str(int(var[0:8], 2)), str(int(var[8:16], 2)), str(int(var[16:24], 2)) , str(int(var[24:32], 2)) ])
            var_formats_dict['bin'] = var
            var_formats_dict['dotted_decimal'] = var_dotted_decimal
        return var_formats_dict

    #反向子网掩码
    def renetmasker(self):
        ip, mask = self.ip, self.mask
        mask = self.maskStyle()
        renetmask_dict = {'renetmask':'', 'bin':''}
        renetmask_dict['bin'] = ''.join([ str(int(i, 2) ^ 1) for i in mask['bin'][:] ])
        renetmask_dict['renetmask'] = self.formatChange(renetmask_dict['bin'], type='bin')['dotted_decimal']
        return renetmask_dict


    #输出子网掩码数字和点分十进制格式，返回字典格式
    def maskStyle(self):
        ip, mask = self.ip, self.mask
        mask_dict = {'digital': '', 'dotted_decimal': '','bin':''}
        #数字/24格式输入，输出点分十进制和二进制
        if mask in mask_mod:
            mask_dict['digital'] = mask
            mask_dict['dotted_decimal'] = mask_mod[mask]
            mask_dict['bin'] = self.formatChange(mask_dict['dotted_decimal'])['bin']
        #点分十进制输入，输出数字/24和二进制
        elif mask in mask_mod.values():
            for key, value in mask_mod.items():
                if mask == value:
                    mask_dict['digital'] = key
                    mask_dict['dotted_decimal'] = mask
                    mask_dict['bin'] = self.formatChange(mask)['bin']
        return mask_dict

    #子网号计算
    def nider(self):
        ip, mask = self.ip, self.mask
        ip = self.formatChange(ip)
        netmask = self.maskStyle()
        nid = str( bin(int(ip['bin'], 2) & int(netmask['bin'], 2)).split('b')[1] ).zfill(32)
        nid_dict = self.formatChange(nid, type='bin')
        return nid_dict

    #广播号计算
    def brder(self):
        ip, mask = self.ip, self.mask
        nid = self.nider()
        renetmask = self.renetmasker()
        brd = bin( int(nid['bin'], 2) ^ int(renetmask['bin'], 2) ).split('b')[1].zfill(32)
        brd_dict = self.formatChange(brd, type='bin')
        return brd_dict

    #可用主机范围
    def iprange(self):
        ip, mask, nid, brd = self.ip, self.mask, self.nider(), self.brder()
        if mask == '32' or mask == '255.255.255.255':
            start_ip_dict = end_ip_dict = self.formatChange(ip)
        else:
            start_ip = bin(int(nid['bin'], 2) + 1).split('b')[1].zfill(32)
            end_ip = bin(int(brd['bin'], 2) - 1).split('b')[1].zfill(32)
            start_ip_dict = self.formatChange(start_ip, type='bin')
            end_ip_dict = self.formatChange(end_ip, type='bin')
        ip_range_dict = {'start_ip': start_ip_dict, 'end_ip': end_ip_dict}
        return ip_range_dict

    # 这里根据需求需要计算出每一个IP地址，后提的需求就单独加了一个方法
    def iprangegenerator(self):
        # ip_range, ip_range_detail = self.iprange(), []
        ip_range = self.iprange()
        start_ip = int(ip_range['start_ip']['bin'], 2)
        end_ip = int(ip_range['end_ip']['bin'], 2)
        for i in range(start_ip, end_ip + 1):
            ipbin = bin(i).split('b')[-1]
            ip = self.formatChange(ipbin, 'bin')
            yield ip
            # ip_range_detail.append(ip)
        # 这里传过去的是生成器，防止占用内存
        # return ip_range_detail



def ipz(ip, netmask):
    ipa = Requirements(ip, netmask)
    if not ipa.formatCheck()['errcode']:
        ip_range = ipa.iprange()
        nid = ipa.nider()
        brd = ipa.brder()
        ip = ipa.formatChange(ip)
        netmask = ipa.maskStyle()
        renetmask = ipa.renetmasker()
        ip_range_generator = ipa.iprangegenerator()#收到的是个list
        ipinfo = {'ip': ip,
                  'nid': nid,
                  'brd': brd,
                  'ip_range': ip_range,
                  'netmask': netmask,
                  'renetmask': renetmask,
                  'errcode': 0,
                  'ip_range_generator': ip_range_generator,
                   }
        return ipinfo
    else:
        ipinfo = {'errcode': ipa.formatCheck()['errcode'],
                  'errmsg': ipa.formatCheck()['errmsg'],
                  }
        return ipinfo


def main():
    args = docopt(__doc__, version='ipz 1.2')
    kwargs = {
       'ip': args['<ip>'],
       'netmask': args['<netmask>'],
    }
    ip = ipz(**kwargs)
    if not ip['errcode'] and not args['range']:
        print("IPa: {0[ip][dotted_decimal]}/{0[netmask][digital]}".format(ip))
        print("Nid: {0[nid][dotted_decimal]}/{0[netmask][digital]}".format(ip))
        print("SIP: {0[ip_range][start_ip][dotted_decimal]}".format(ip))
        print("EIP: {0[ip_range][end_ip][dotted_decimal]}".format(ip))
        print("Brd: {0[brd][dotted_decimal]}".format(ip))
    elif not ip['errcode'] and args['range']:
        print('You can use IP in {0[ip]} network segment:'.format(kwargs))
        for i in ip['ip_range_generator']:
            print(i['dotted_decimal'])
    else:
        print("{0[errmsg]}".format(ip))

if __name__ == '__main__':
    main()
