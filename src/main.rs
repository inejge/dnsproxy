extern crate futures;
extern crate fnv;
#[macro_use] extern crate lazy_static;
extern crate tokio_core;
extern crate toml;
extern crate trust_dns;
extern crate trust_dns_server;

use std::cell::RefCell;
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::{self, Read};
use std::net::{SocketAddr, UdpSocket};
use std::rc::Rc;

use fnv::FnvHashMap;
use futures::{Future, Stream, future};
use tokio_core::reactor::Core;
use trust_dns::client::{ClientFuture, ClientHandle};
use trust_dns::udp::{UdpStream, UdpClientStream};
use trust_dns::op::{Message, ResponseCode};
use trust_dns::rr::{DNSClass, Name, RecordType};
use trust_dns::rr::record_data::RData;
use trust_dns_server::server::RequestStream;

enum AnsOp {
    CollapseCNAMEChain,
    TrimAddrList(u32),
    AdjustTTL(u32),
    DiscardAAAA,
}

struct ProxyEndpoint {
    io_loop: Core,
    upstream_dns: SocketAddr,
    name_map: Rc<RefCell<FnvHashMap<Name, Vec<AnsOp>>>>,
}

lazy_static! {
    static ref ROOT: Name = {
        Name::root()
    };
}

impl ProxyEndpoint {
    fn new(upstream: &str) -> io::Result<ProxyEndpoint> {
        let mut server_port = String::from(upstream);
        if upstream.find(':').is_none() {
            server_port.push_str(":53");
        }
        let upstream_dns = try!((&server_port).parse::<SocketAddr>().map_err(|e| other(e.description())));
        Ok(ProxyEndpoint {
            io_loop: try!(Core::new()),
            upstream_dns: upstream_dns,
            name_map: Rc::new(RefCell::new(FnvHashMap::default())),
        })
    }

    fn add_name_with_ops(&self, name: &str, ops: Vec<&str>) -> io::Result<()> {
        let dns_name = try!(Name::parse(name, Some(&ROOT)).map_err(|e| other(&format!("error parsing `{}': {}", name, e.description()))));
        if self.name_map.borrow().contains_key(&dns_name) {
            return Err(other(&format!("name `{}' already in map", name)));
        }
        let mut op_vec = Vec::new();
        for str_op in ops {
            match str_op {
                "collapse_cname_chain" => {
                    op_vec.push(AnsOp::CollapseCNAMEChain);
                    continue;
                },
                "discard_aaaa" => {
                    op_vec.push(AnsOp::DiscardAAAA);
                    continue;
                },
                _ => (),
            }
            if str_op.starts_with("trim_addr_list:") {
                let mut name_val = str_op.split(':');
                name_val.next().expect("tr_name");
                let val = try!(name_val.next().expect("tr_val").parse::<u32>().map_err(|e| other(e.description())));
                op_vec.push(AnsOp::TrimAddrList(val));
                continue;
            }
            if str_op.starts_with("adjust_ttl:") {
                let mut name_val = str_op.split(':');
                name_val.next().expect("ttl_name");
                let val = try!(name_val.next().expect("ttl_val").parse::<u32>().map_err(|e| other(e.description())));
                op_vec.push(AnsOp::AdjustTTL(val));
                continue;
            }
            return Err(other(&format!("unrecognized op: {}", str_op)));
        }
        if op_vec.len() == 0 {
            return Err(other(&format!("empty op list for `{}'", name)));
        }
        self.name_map.borrow_mut().insert(dns_name, op_vec);
        Ok(())
    }

    fn listen(&mut self, socket: UdpSocket) {
        let (buf_stream, stream_handle) = UdpStream::with_bound(socket, self.io_loop.handle());
        let request_stream = RequestStream::new(buf_stream, stream_handle);
        let handle = self.io_loop.handle();
        let upstream_dns = self.upstream_dns.clone();
        let name_map = self.name_map.clone();
        let queries = request_stream.map(|(request, response_handle)| {
            if request.message.get_queries().len() != 1 {
                return mybox(future::err(other("not exactly one query in question section")));
            }
            let qname = request.message.get_queries()[0].get_name().clone();
            let qtype = request.message.get_queries()[0].get_query_type();
            let qclass = request.message.get_queries()[0].get_query_class();
            let name_map = name_map.clone();
            let (stream, sender) = UdpClientStream::new(upstream_dns, handle.clone());
            let mut client = ClientFuture::new(stream, sender, handle.clone(), None);
            mybox(client.query(qname.clone(), qclass, qtype)
                    .map_err(|e| other(&format!("dns error: {}", e)))
                    .and_then(move |mut response| {
                if response.get_response_code() == ResponseCode::NoError && qclass == DNSClass::IN {
		    if let Some(ops) = name_map.borrow().get(&qname) {
			response = process_response(response, ops);
		    }
		}
                response.id(request.message.get_id());
                future::ok((response_handle, response))
            }))
        });
        let handle = self.io_loop.handle();
        let server = queries.for_each(|query| {
            handle.spawn(query.then(|res| {
                match res {
                    Ok((mut response_handle, response)) => {
                        if let Err(_e) = response_handle.send(response) {
                            // TODO debug logging
                        }
                    },
                    Err(_e) => (), // TODO debug logging
                }
                future::ok(())
            }));
            Ok(())
        });
        self.io_loop.run(server).unwrap();
    }
}

fn process_response(mut response: Message, ops: &Vec<AnsOp>) -> Message {
    let mut answers = response.take_answers();

    // CNAME processing
    let mut have_collapse_cname_chain = false;
    let mut cname_chain = Vec::new();
    let mut have_valid_cname_chain = true;
    let mut last_cname = None;
    let mut last_was_cname = false;

    // Address list trimming
    let mut have_trim_addr_list = false;
    let mut trim_ids = Vec::new();
    let mut a_count = 0;
    let mut r_count = 0;

    // TTL adjustment
    let mut have_adjust_ttl = false;
    let mut minimum_ttl = 0;

    // AAAA discarding
    let mut have_discard_aaaa = false;
    let mut do_discard_aaaa = false;

    for op in ops {
        match *op {
            AnsOp::CollapseCNAMEChain => have_collapse_cname_chain = true,
            AnsOp::TrimAddrList(count) => {
                have_trim_addr_list = true;
                r_count = count;
            },
            AnsOp::AdjustTTL(value) => {
                have_adjust_ttl = true;
                minimum_ttl = value;
            },
            AnsOp::DiscardAAAA => have_discard_aaaa = true,
        }
    }

    for (idx, answer) in answers.iter().enumerate() {
        match answer.get_rr_type() {
            RecordType::CNAME => {
                last_was_cname = true;
                if have_collapse_cname_chain {
                    let cname = match answer.get_rdata() {
                        &RData::CNAME(ref rdata) => rdata.clone(),
                        _ => unreachable!(),
                    };
                    if idx == 0 {
                        cname_chain.push(cname);
                    } else if answer.get_name() == cname_chain.last().expect("cname") {
                        cname_chain.push(cname);
                        trim_ids.push(idx);
                    } else {
                        have_valid_cname_chain = false;
                    }
                }
            },
            rt @ RecordType::A | rt @ RecordType::AAAA => {
                if have_collapse_cname_chain && last_was_cname {
                    last_was_cname = false;
                    if have_valid_cname_chain && answer.get_name() == cname_chain.last().expect("cname") {
                        if let Some(cname) = cname_chain.pop() {
                            last_cname = Some(cname);
                        }
                    } else {
                        trim_ids.clear();
                    }
                }
                if have_trim_addr_list {
                    a_count += 1;
                    if a_count > r_count {
                        trim_ids.push(idx);
                    }
                }
                if have_discard_aaaa && rt == RecordType::AAAA {
                    do_discard_aaaa = true;
                }
            }
            _ => (),
        }
    }
    if have_collapse_cname_chain && last_was_cname && have_valid_cname_chain {
        answers[0].rdata(RData::CNAME(cname_chain.last().expect("cname").clone()));
    }
    if do_discard_aaaa {
        answers.clear();
        trim_ids.clear();
    }
    trim_ids.reverse();
    for id in trim_ids {
        answers.remove(id);
    }
    match last_cname {
        Some(ref cname) if answers.len() > 0 => { answers[0].rdata(RData::CNAME(cname.clone())); },
        _ => (),
    }
    if have_adjust_ttl {
        for answer in answers.iter_mut() {
            if answer.get_ttl() < minimum_ttl {
                answer.ttl(minimum_ttl);
            }
        }
    }
    response.insert_answers(answers);
    response
}

fn other(desc: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, desc)
}

fn mybox<F: Future + 'static>(f: F) -> Box<Future<Item=F::Item, Error=F::Error>> {
    Box::new(f)
}

fn main() {
    let mut args = env::args();
    args.next().expect("progname");
    let config_file = args.next().unwrap_or("/etc/dnsproxy.toml".to_owned());
    let mut config = String::new();
    match File::open(&config_file) {
        Ok(mut file) => { file.read_to_string(&mut config).unwrap_or_else(|e| panic!("reading config: {}", e)); },
        Err(e) => panic!("config file {}: {}", config_file, e),
    }

    let toml = match toml::Parser::new(&config).parse() {
        None => panic!("failed to parse config"),
        Some(t) => toml::Value::Table(t),
    };

    let local = toml.lookup("servers.local").map(toml::Value::as_str).unwrap_or(Some("127.0.0.1:5353")).expect("local");
    let upstream = match toml.lookup("servers.upstream") {
        None => panic!("no upstream server in config"),
        Some(ref v) => v.as_str().expect("upstream"),
    };
    let mut proxy = ProxyEndpoint::new(upstream).expect("proxy");

    match toml.lookup("rules") {
        Some(rules) => for rule in rules.as_slice().expect("rules") {
            let name = match rule.lookup("name") {
                None => panic!("nameless rules not permitted"),
                Some(n) => n.as_str().expect("name"),
            };
            let t_ops = match rule.lookup("ops") {
                None => panic!("no ops for name: {}", name),
                Some(o) => o.as_slice().expect("ops"),
            };
            let mut ops = Vec::new();
            for op in t_ops {
                ops.push(op.as_str().expect("op"));
            }
            proxy.add_name_with_ops(name, ops).expect("add_name");
        },
        None => (),
    }

    let socket = UdpSocket::bind(local).expect("socket");
    proxy.listen(socket);
}
