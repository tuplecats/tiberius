extern crate tiberius;
use tiberius::Client;

#[test]
fn main()
{
    //let mut test = vec![];
    //let mut cl = Client::new(test);
    let mut cl = Client::connect_tcp("127.0.0.1", 1433).unwrap();
    cl.initialize_connection().unwrap();
    let rows = cl.exec("SELECT * FROM [test].[dbo].[test];").unwrap();
    println!("rows: {:?}", rows);
    //let mut buffer = [0; 4096];
    //cl.stream.read(&mut buffer).unwrap();
    //println!("{:?}", buffer.to_vec());
    //println!("{:?}", cl.stream);
}
