# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "fastercsv"
require "ipaddress"

# The cvslookup filter allows you to add fields to an event
# base on a csv file

class LogStash::Filters::CSVLookup < LogStash::Filters::Base
  config_name "CSVLookup"
  milestone 1

  # Example:
  #
  #     filter {
  #       CSVLookup {
  #         file => "key_value.csv"
  #         key_col => 1
  #         value_col => 2
  #         default => "some_value"
  #         map_field => { "from_field" => "to_field" }
  #         network => true
  #       }
  #     }
  #
  # the default is used if the key_col's value is not present in the CSV file

  config :file, :validate => :string, :required => true
  config :key_col, :validate => :number, :default => 1, :required => false
  config :value_col, :validate => :number, :default => 2, :required => false
  config :default, :validate => :string, :required => false
  config :map_field, :validate => :hash, :required => true
  config :network, :validate => :boolean, :required => true
  
  public
  def register
  	 loadFile()
    #puts @lookup.inspect
  end # def register

  public
  def loadFile
    @lookup = Hash.new
    @checkNetwork = Hash.new

    CSV.foreach(@file) do |row|
      @lookup[row[@key_col - 1]] = row[@value_col - 1]
	  if @network
        @checkNetwork[row[@key_col - 1]] = IPAddress(row[@key_col - 1])
	  end
    end
  end
  
  public
  def filter(event)
    return unless filter?(event)
	looked_up_val = ""
	if @network
		@map_field.each do |src_field,dest_field|
		@checkNetwork.each {|key, value|
		  if value.include?(IPAddress(event[src_field].to_s))
		  looked_up_val = @lookup[key]
		  end
		}
		  if looked_up_val.nil?
			  if !@default.nil?
				event[dest_field] = @default
			  end
		  else
			  event[dest_field] = looked_up_val
		  end
		end
	else
		@map_field.each do |src_field,dest_field|
		  looked_up_val = @lookup[event[src_field].to_s]
		  if looked_up_val.nil?
			  if !@default.nil?
				event[dest_field] = @default
			  end
		  else
			  event[dest_field] = looked_up_val
		  end
		end
	end
  end # def filter
end # class LogStash::Filters::CSVLookup
